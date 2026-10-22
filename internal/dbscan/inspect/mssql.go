package inspect

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	_ "github.com/microsoft/go-mssqldb" // database/sql driver "sqlserver"

	"github.com/ininia/scanx/internal/dbscan"
)

type mssqlEngine struct{}

func (mssqlEngine) open(ctx context.Context, r Request) (*sql.DB, *sql.Conn, error) {
	q := url.Values{}
	if r.Database != "" {
		q.Set("database", r.Database)
	}
	q.Set("app name", "scanX")
	q.Set("dial timeout", "15")
	q.Set("connection timeout", "120")
	// Routed to a readable secondary when the server is in an availability
	// group; ignored otherwise.
	q.Set("ApplicationIntent", "ReadOnly")
	switch r.TLS {
	case TLSDisable:
		q.Set("encrypt", "disable")
	case TLSVerify:
		q.Set("encrypt", "true")
	default:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "true")
	}
	u := url.URL{
		Scheme: "sqlserver", User: url.UserPassword(r.User, r.Password),
		Host: net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), RawQuery: q.Encode(),
	}
	// SQL Server has no read-only session mode: scanX only ever runs catalog
	// SELECTs, and the account is verified to have no write permission.
	return openConn(ctx, "sqlserver", u.String(),
		"SET LOCK_TIMEOUT 5000", "SET DEADLOCK_PRIORITY LOW", "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
}

// Server- and database-level permissions compatible with a read-only
// account. Everything else (CONTROL, ALTER..., INSERT, EXECUTE...) blocks.
var (
	mssqlServerAllowed = map[string]bool{
		"CONNECT SQL": true, "VIEW ANY DATABASE": true, "VIEW ANY DEFINITION": true, "VIEW SERVER STATE": true,
		"VIEW SERVER PERFORMANCE STATE": true, "VIEW SERVER SECURITY STATE": true, "VIEW ANY SECURITY DEFINITION": true,
		"VIEW ANY PERFORMANCE DEFINITION": true, "CONNECT ANY DATABASE": true, "SELECT ALL USER SECURABLES": true,
		"VIEW ANY ERROR LOG": true, "VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION": true,
	}
	mssqlDBAllowed = map[string]bool{
		"CONNECT": true, "SELECT": true, "VIEW DEFINITION": true, "VIEW DATABASE STATE": true,
		"VIEW DATABASE PERFORMANCE STATE": true, "VIEW DATABASE SECURITY STATE": true, "SHOWPLAN": true,
		"REFERENCES": true, "VIEW ANY COLUMN MASTER KEY DEFINITION": true, "VIEW ANY COLUMN ENCRYPTION KEY DEFINITION": true,
		"VIEW SECURITY DEFINITION": true, "VIEW PERFORMANCE DEFINITION": true, "VIEW CRYPTOGRAPHICALLY SECURED DEFINITION": true,
	}
)

func (mssqlEngine) verify(ctx context.Context, c *sql.Conn) (*dbscan.ReadOnlyCheck, error) {
	ro := &dbscan.ReadOnlyCheck{}
	var login, user string
	if err := c.QueryRowContext(ctx, "SELECT SUSER_SNAME(), USER_NAME()").Scan(&login, &user); err != nil {
		return nil, err
	}
	ro.User = login + " (database user " + user + ")"

	perms, err := queryStrings(ctx, c, "SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER') ORDER BY 1")
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		switch {
		case mssqlServerAllowed[p]:
			ro.Allowed = append(ro.Allowed, "server: "+p)
		case p == "CONTROL SERVER":
			ro.Violations = append(ro.Violations, "CONTROL SERVER (sysadmin-level access).")
		default:
			ro.Violations = append(ro.Violations, "Server permission "+p+".")
		}
	}
	perms, err = queryStrings(ctx, c, "SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE') ORDER BY 1")
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		switch {
		case mssqlDBAllowed[p]:
			ro.Allowed = append(ro.Allowed, "database: "+p)
		case p == "EXECUTE":
			ro.Violations = append(ro.Violations, "EXECUTE on the database (stored procedures can change data).")
		default:
			ro.Violations = append(ro.Violations, "Database permission "+p+".")
		}
	}
	if len(ro.Violations) > 8 {
		// A db_owner/sysadmin account lists dozens of permissions; keep it readable.
		n := len(ro.Violations)
		ro.Violations = append(ro.Violations[:8], fmt.Sprintf("... and %d more write/admin permissions.", n-8))
	}

	schemas, err := queryStrings(ctx, c, `
SELECT s.name FROM sys.schemas s
WHERE s.schema_id < 16384 AND s.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest')
  AND (HAS_PERMS_BY_NAME(QUOTENAME(s.name), 'SCHEMA', 'ALTER') = 1 OR HAS_PERMS_BY_NAME(QUOTENAME(s.name), 'SCHEMA', 'CONTROL') = 1)
ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	for _, s := range schemas {
		ro.Violations = append(ro.Violations, "ALTER/CONTROL on schema "+s+".")
	}

	writes, err := queryStrings(ctx, c, `
SELECT TOP 25 p.perm + ' on ' + s.name + '.' + o.name
FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('ALTER'), ('CONTROL'), ('TAKE OWNERSHIP')) AS p(perm)
WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
  AND HAS_PERMS_BY_NAME(QUOTENAME(s.name) + '.' + QUOTENAME(o.name), 'OBJECT', p.perm) = 1
ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	for _, w := range writes {
		ro.Violations = append(ro.Violations, "Write privilege: "+w+".")
	}

	var procs, readable int
	if err := c.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM sys.procedures p WHERE p.is_ms_shipped = 0
     AND HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME(p.schema_id)) + '.' + QUOTENAME(p.name), 'OBJECT', 'EXECUTE') = 1),
  (SELECT COUNT(*) FROM sys.objects o WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
     AND HAS_PERMS_BY_NAME(QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name), 'OBJECT', 'SELECT') = 1)`).
		Scan(&procs, &readable); err != nil {
		return nil, err
	}
	if procs > 0 {
		ro.Violations = append(ro.Violations, fmt.Sprintf("EXECUTE on %d stored procedure(s) (procedures can change data).", procs))
	}
	ro.Allowed = append(ro.Allowed, fmt.Sprintf("SELECT on %d tables/views", readable))
	sort.Strings(ro.Allowed)
	ro.OK = len(ro.Violations) == 0
	return ro, nil
}

func (mssqlEngine) snapshot(ctx context.Context, c *sql.Conn, _ Request) (*dbscan.Snapshot, error) {
	s := &dbscan.Snapshot{}
	if err := c.QueryRowContext(ctx, `
SELECT DB_NAME(), CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) + ' ' + CAST(SERVERPROPERTY('Edition') AS nvarchar(128)),
       CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128))`).Scan(&s.Database, &s.ServerVersion, &s.Collation); err != nil {
		return nil, err
	}

	byID := map[int64]*dbscan.Table{}
	var ids []int64
	err := each(ctx, c, `
SELECT TOP (@p1) t.object_id, s.name, t.name,
       ISNULL((SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = t.object_id AND p.index_id IN (0, 1)), 0),
       ISNULL(CAST(ep.value AS nvarchar(2000)), '')
FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
LEFT JOIN sys.extended_properties ep ON ep.class = 1 AND ep.major_id = t.object_id AND ep.minor_id = 0 AND ep.name = 'MS_Description'
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name`, func(rows *sql.Rows) error {
		var id int64
		var t dbscan.Table
		if err := rows.Scan(&id, &t.Schema, &t.Name, &t.RowEst, &t.Comment); err != nil {
			return err
		}
		s.Tables = append(s.Tables, t)
		ids = append(ids, id)
		return nil
	}, MaxTables+1)
	if err != nil {
		return nil, err
	}
	if len(s.Tables) > MaxTables {
		s.Tables, ids, s.Truncated = s.Tables[:MaxTables], ids[:MaxTables], true
	}
	for i := range s.Tables {
		byID[ids[i]] = &s.Tables[i]
	}

	err = each(ctx, c, `
SELECT c.object_id, c.name, LOWER(ty.name), c.max_length, c.precision, c.scale, c.is_nullable,
       ISNULL(dc.definition, ''), c.is_identity, ISNULL(c.collation_name, ''),
       CASE WHEN c.is_identity = 1 THEN CAST(CAST(IDENT_CURRENT(QUOTENAME(s.name) + '.' + QUOTENAME(t.name)) AS decimal(38, 0)) AS nvarchar(40)) ELSE '' END
FROM sys.columns c
JOIN sys.tables t ON t.object_id = c.object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.types ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.default_constraints dc ON dc.object_id = c.default_object_id
WHERE t.is_ms_shipped = 0
ORDER BY c.object_id, c.column_id`, func(rows *sql.Rows) error {
		var id int64
		var maxLen, prec, scale int
		var ident string
		var col dbscan.Column
		if err := rows.Scan(&id, &col.Name, &col.DataType, &maxLen, &prec, &scale, &col.Nullable, &col.Default,
			&col.Identity, &col.Collation, &ident); err != nil {
			return err
		}
		col.FullType, col.Length = mssqlFullType(col.DataType, maxLen, prec, scale)
		if v, err := strconv.ParseInt(ident, 10, 64); err == nil {
			col.IdentityValue = v
		}
		if t := byID[id]; t != nil {
			t.Columns = append(t.Columns, col)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var cur *dbscan.Index
	var curObj, curIdx int64
	err = each(ctx, c, `
SELECT i.object_id, i.index_id, ISNULL(i.name, ''), i.is_unique, i.is_primary_key, col.name
FROM sys.indexes i
JOIN sys.tables t ON t.object_id = i.object_id
JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
JOIN sys.columns col ON col.object_id = ic.object_id AND col.column_id = ic.column_id
WHERE t.is_ms_shipped = 0 AND i.type > 0 AND i.is_hypothetical = 0
ORDER BY i.object_id, i.index_id, ic.key_ordinal`, func(rows *sql.Rows) error {
		var obj, idx int64
		var name, col string
		var unique, primary bool
		if err := rows.Scan(&obj, &idx, &name, &unique, &primary, &col); err != nil {
			return err
		}
		t := byID[obj]
		if t == nil {
			return nil
		}
		if cur == nil || obj != curObj || idx != curIdx {
			t.Indexes = append(t.Indexes, dbscan.Index{Name: name, Unique: unique, Primary: primary})
			cur, curObj, curIdx = &t.Indexes[len(t.Indexes)-1], obj, idx
		}
		cur.Columns = append(cur.Columns, col)
		return nil
	})
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
	curObj = 0
	err = each(ctx, c, `
SELECT fk.parent_object_id, fk.name, pc.name, rs.name, rt.name, rc.name
FROM sys.foreign_keys fk
JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
JOIN sys.tables rt ON rt.object_id = fkc.referenced_object_id
JOIN sys.schemas rs ON rs.schema_id = rt.schema_id
JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
ORDER BY fk.parent_object_id, fk.name, fkc.constraint_column_id`, func(rows *sql.Rows) error {
		var obj int64
		var name, col, refSchema, refTable, refCol string
		if err := rows.Scan(&obj, &name, &col, &refSchema, &refTable, &refCol); err != nil {
			return err
		}
		t := byID[obj]
		if t == nil {
			return nil
		}
		if curFK == nil || obj != curObj || curFK.Name != name {
			t.ForeignKey = append(t.ForeignKey, dbscan.ForeignKey{Name: name, RefSchema: refSchema, RefTable: refTable})
			curFK, curObj = &t.ForeignKey[len(t.ForeignKey)-1], obj
		}
		curFK.Columns = append(curFK.Columns, col)
		curFK.RefColumns = append(curFK.RefColumns, refCol)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = each(ctx, c, `
SELECT SCHEMA_NAME(o.schema_id), o.name, o.type FROM sys.objects o
WHERE o.is_ms_shipped = 0 AND o.type IN ('V', 'P', 'FN', 'IF', 'TF')
ORDER BY 1, 2`, func(rows *sql.Rows) error {
		var schema, name, typ string
		if err := rows.Scan(&schema, &name, &typ); err != nil {
			return err
		}
		switch strings.TrimSpace(typ) {
		case "V":
			s.Views = append(s.Views, dbscan.View{Schema: schema, Name: name})
		case "P":
			s.Routines = append(s.Routines, dbscan.Routine{Schema: schema, Name: name, Kind: "procedure"})
		default:
			s.Routines = append(s.Routines, dbscan.Routine{Schema: schema, Name: name, Kind: "function"})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Grants to PUBLIC are optional evidence: an account without the
	// permission to see them simply reports none.
	_ = each(ctx, c, `
SELECT TOP 2000 SCHEMA_NAME(o.schema_id), o.name, p.permission_name
FROM sys.database_permissions p JOIN sys.objects o ON o.object_id = p.major_id
WHERE p.class = 1 AND p.grantee_principal_id = DATABASE_PRINCIPAL_ID('public') AND p.state IN ('G', 'W')
  AND o.is_ms_shipped = 0 AND o.type IN ('U', 'V')
ORDER BY 1, 2, 3`, func(rows *sql.Rows) error {
		var g dbscan.Grant
		if err := rows.Scan(&g.Schema, &g.Table, &g.Privilege); err != nil {
			return err
		}
		s.PublicGrants = append(s.PublicGrants, g)
		return nil
	})
	return s, nil
}

// mssqlFullType rebuilds the declared type from sys.columns.
func mssqlFullType(t string, maxLen, prec, scale int) (string, int) {
	switch t {
	case "varchar", "char", "varbinary", "binary":
		if maxLen < 0 {
			return t + "(max)", 0
		}
		return fmt.Sprintf("%s(%d)", t, maxLen), maxLen
	case "nvarchar", "nchar":
		if maxLen < 0 {
			return t + "(max)", 0
		}
		return fmt.Sprintf("%s(%d)", t, maxLen/2), maxLen / 2
	case "decimal", "numeric":
		return fmt.Sprintf("%s(%d,%d)", t, prec, scale), 0
	case "datetime2", "datetimeoffset", "time":
		return fmt.Sprintf("%s(%d)", t, scale), 0
	}
	return t, 0
}
