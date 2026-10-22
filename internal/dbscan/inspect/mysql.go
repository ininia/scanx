package inspect

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ininia/scanx/internal/dbscan"
)

type mysqlEngine struct{}

func (mysqlEngine) open(ctx context.Context, r Request) (*sql.DB, *sql.Conn, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = r.User, r.Password
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), r.Database
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 15*time.Second, 2*time.Minute, time.Minute
	cfg.AllowNativePasswords = true
	cfg.Params = map[string]string{"charset": "utf8mb4"}
	switch r.TLS {
	case TLSDisable:
		cfg.TLSConfig = "false"
	case TLSVerify:
		cfg.TLSConfig = "true"
	default:
		cfg.TLSConfig = "skip-verify"
	}
	// The whole session is read-only: any write statement fails.
	return openConn(ctx, "mysql", cfg.FormatDSN(), "SET SESSION TRANSACTION READ ONLY")
}

// mysqlAllowed are the only privileges a read-only account may hold.
var mysqlAllowed = map[string]bool{"USAGE": true, "SELECT": true, "SHOW VIEW": true, "SHOW DATABASES": true}

var (
	grantRe    = regexp.MustCompile(`(?is)^GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+.+$`)
	roleGrant  = regexp.MustCompile(`(?is)^GRANT\s+(.+?)\s+TO\s+.+$`)
	columnList = regexp.MustCompile(`\s*\([^)]*\)`)
)

// parseGrants checks SHOW GRANTS lines. It returns the role list found
// in "GRANT role TO user" lines (their privileges are checked separately).
func parseGrants(lines []string, ro *dbscan.ReadOnlyCheck) (roles []string) {
	seen := map[string]bool{}
	for _, line := range lines {
		l := strings.TrimSpace(line)
		upper := strings.ToUpper(l)
		if strings.HasPrefix(upper, "REVOKE") {
			continue // partial revokes only remove privileges
		}
		if m := grantRe.FindStringSubmatch(l); m != nil {
			obj := strings.TrimSpace(m[2])
			if strings.HasPrefix(strings.ToUpper(m[1]), "PROXY") {
				ro.Violations = append(ro.Violations, "PROXY privilege (can act as another account).")
				continue
			}
			for _, p := range strings.Split(columnList.ReplaceAllString(m[1], ""), ",") {
				p = strings.ToUpper(strings.TrimSpace(p))
				if p == "" {
					continue
				}
				if mysqlAllowed[p] {
					if key := p + " ON " + obj; !seen[key] {
						seen[key] = true
						ro.Allowed = append(ro.Allowed, key)
					}
					continue
				}
				ro.Violations = append(ro.Violations, fmt.Sprintf("%s ON %s", p, obj))
			}
			if strings.Contains(upper, "WITH GRANT OPTION") {
				ro.Violations = append(ro.Violations, "WITH GRANT OPTION ON "+obj+" (can grant privileges to others).")
			}
			continue
		}
		if m := roleGrant.FindStringSubmatch(l); m != nil {
			for _, r := range strings.Split(m[1], ",") {
				if r = strings.TrimSpace(r); r != "" {
					roles = append(roles, r)
				}
			}
			if strings.Contains(upper, "WITH ADMIN OPTION") {
				ro.Violations = append(ro.Violations, "WITH ADMIN OPTION on roles "+m[1]+".")
			}
		}
	}
	return roles
}

func showGrants(ctx context.Context, c *sql.Conn, q string) ([]string, error) {
	return queryStrings(ctx, c, q)
}

func (mysqlEngine) verify(ctx context.Context, c *sql.Conn) (*dbscan.ReadOnlyCheck, error) {
	ro := &dbscan.ReadOnlyCheck{}
	if err := c.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&ro.User); err != nil {
		return nil, err
	}
	lines, err := showGrants(ctx, c, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		return nil, err
	}
	roles := parseGrants(lines, ro)
	if len(roles) > 0 {
		// MySQL 8: expand the roles' privileges; MariaDB: ask per role.
		expanded, err := showGrants(ctx, c, "SHOW GRANTS FOR CURRENT_USER() USING "+strings.Join(roles, ", "))
		if err == nil {
			parseGrants(expanded, ro)
		} else {
			for _, r := range roles {
				rl, err := showGrants(ctx, c, "SHOW GRANTS FOR "+r)
				if err != nil {
					ro.Violations = append(ro.Violations, "Cannot check the privileges of role "+r+".")
					continue
				}
				parseGrants(rl, ro)
			}
		}
	}
	sort.Strings(ro.Allowed)
	ro.Violations = dedupe(ro.Violations)
	ro.Allowed = append(ro.Allowed, "session forced read-only")
	ro.OK = len(ro.Violations) == 0
	return ro, nil
}

func (mysqlEngine) snapshot(ctx context.Context, c *sql.Conn, r Request) (*dbscan.Snapshot, error) {
	s := &dbscan.Snapshot{Database: r.Database}
	_ = c.QueryRowContext(ctx, "SELECT VERSION()").Scan(&s.ServerVersion)
	if s.Database == "" {
		_ = c.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&s.Database)
	}
	_ = c.QueryRowContext(ctx, `SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`,
		s.Database).Scan(&s.CharSet, &s.Collation)

	byName := map[string]*dbscan.Table{}
	autoInc := map[string]int64{}
	err := each(ctx, c, `
SELECT TABLE_NAME, TABLE_TYPE, COALESCE(ENGINE, ''), COALESCE(TABLE_ROWS, 0), COALESCE(TABLE_COLLATION, ''),
       COALESCE(TABLE_COMMENT, ''), COALESCE(AUTO_INCREMENT, 0)
FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`, func(rows *sql.Rows) error {
		var t dbscan.Table
		var typ string
		var ai int64
		if err := rows.Scan(&t.Name, &typ, &t.StorageEngine, &t.RowEst, &t.Collation, &t.Comment, &ai); err != nil {
			return err
		}
		switch {
		case typ == "VIEW" || typ == "SYSTEM VIEW":
			s.Views = append(s.Views, dbscan.View{Name: t.Name})
		case len(s.Tables) >= MaxTables:
			s.Truncated = true
		default:
			s.Tables = append(s.Tables, t)
			autoInc[t.Name] = ai
		}
		return nil
	}, s.Database)
	if err != nil {
		return nil, err
	}
	for i := range s.Tables {
		byName[s.Tables[i].Name] = &s.Tables[i]
	}

	err = each(ctx, c, `
SELECT TABLE_NAME, COLUMN_NAME, LOWER(DATA_TYPE), LOWER(COLUMN_TYPE), COALESCE(CHARACTER_MAXIMUM_LENGTH, 0), IS_NULLABLE,
       COALESCE(COLUMN_DEFAULT, ''), LOWER(EXTRA), COALESCE(COLLATION_NAME, ''), COALESCE(COLUMN_COMMENT, '')
FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, ORDINAL_POSITION`, func(rows *sql.Rows) error {
		var table, nullable, extra string
		var length int64
		var col dbscan.Column
		if err := rows.Scan(&table, &col.Name, &col.DataType, &col.FullType, &length, &nullable, &col.Default, &extra,
			&col.Collation, &col.Comment); err != nil {
			return err
		}
		col.Nullable = nullable == "YES"
		if length > 0 && length < 1<<31 {
			col.Length = int(length)
		}
		col.Identity = strings.Contains(extra, "auto_increment")
		if t := byName[table]; t != nil {
			if col.Identity {
				col.IdentityValue = autoInc[table]
			}
			t.Columns = append(t.Columns, col)
		}
		return nil
	}, s.Database)
	if err != nil {
		return nil, err
	}

	var cur *dbscan.Index
	var curTable string
	err = each(ctx, c, `
SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, COALESCE(COLUMN_NAME, '')
FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`, func(rows *sql.Rows) error {
		var table, name, col string
		var nonUnique int
		if err := rows.Scan(&table, &name, &nonUnique, &col); err != nil {
			return err
		}
		t := byName[table]
		if t == nil {
			return nil
		}
		if cur == nil || curTable != table || cur.Name != name {
			t.Indexes = append(t.Indexes, dbscan.Index{Name: name, Unique: nonUnique == 0, Primary: name == "PRIMARY"})
			cur, curTable = &t.Indexes[len(t.Indexes)-1], table
		}
		if col != "" {
			cur.Columns = append(cur.Columns, col)
		}
		return nil
	}, s.Database)
	if err != nil {
		return nil, err
	}
	for i := range s.Tables {
		for _, ix := range s.Tables[i].Indexes {
			if ix.Primary {
				s.Tables[i].PrimaryKey = ix.Columns
			}
		}
	}

	var curFK *dbscan.ForeignKey
	curTable = ""
	err = each(ctx, c, `
SELECT TABLE_NAME, CONSTRAINT_NAME, COLUMN_NAME, COALESCE(REFERENCED_TABLE_SCHEMA, ''), REFERENCED_TABLE_NAME, COALESCE(REFERENCED_COLUMN_NAME, '')
FROM information_schema.KEY_COLUMN_USAGE
WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION`, func(rows *sql.Rows) error {
		var table, name, col, refSchema, refTable, refCol string
		if err := rows.Scan(&table, &name, &col, &refSchema, &refTable, &refCol); err != nil {
			return err
		}
		t := byName[table]
		if t == nil {
			return nil
		}
		if curFK == nil || curTable != table || curFK.Name != name {
			if refSchema == s.Database {
				refSchema = ""
			}
			t.ForeignKey = append(t.ForeignKey, dbscan.ForeignKey{Name: name, RefSchema: refSchema, RefTable: refTable})
			curFK, curTable = &t.ForeignKey[len(t.ForeignKey)-1], table
		}
		curFK.Columns = append(curFK.Columns, col)
		curFK.RefColumns = append(curFK.RefColumns, refCol)
		return nil
	}, s.Database)
	if err != nil {
		return nil, err
	}

	// Routine names are optional (visible only with some privilege on them).
	_ = each(ctx, c, `
SELECT ROUTINE_NAME, LOWER(ROUTINE_TYPE) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? ORDER BY ROUTINE_NAME`,
		func(rows *sql.Rows) error {
			var rt dbscan.Routine
			if err := rows.Scan(&rt.Name, &rt.Kind); err != nil {
				return err
			}
			s.Routines = append(s.Routines, rt)
			return nil
		}, s.Database)
	return s, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
