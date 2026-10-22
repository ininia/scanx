package inspect

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"

	"github.com/ininia/scanx/internal/dbscan"
)

type postgresEngine struct{}

// pgUserSchemas excludes the catalog schemas from every query.
const pgUserSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'`

// pgNotExtension skips objects created by extensions (PostGIS tables...).
const pgNotExtension = `NOT EXISTS (SELECT 1 FROM pg_depend dx WHERE dx.classid = 'pg_class'::regclass AND dx.objid = c.oid AND dx.deptype = 'e')`

func (postgresEngine) open(ctx context.Context, r Request) (*sql.DB, *sql.Conn, error) {
	ssl := "require"
	switch r.TLS {
	case TLSDisable:
		ssl = "disable"
	case TLSVerify:
		ssl = "verify-full"
	}
	q := url.Values{}
	q.Set("sslmode", ssl)
	q.Set("connect_timeout", "15")
	q.Set("application_name", "scanX")
	// Startup parameters: every transaction of the session is read-only
	// and no statement may run longer than a minute.
	q.Set("default_transaction_read_only", "on")
	q.Set("statement_timeout", "60000")
	q.Set("lock_timeout", "5000")
	u := url.URL{
		Scheme: "postgres", User: url.UserPassword(r.User, r.Password),
		Host: net.JoinHostPort(r.Host, strconv.Itoa(r.Port)), Path: "/" + r.Database, RawQuery: q.Encode(),
	}
	return openConn(ctx, "pgx", u.String())
}

func (postgresEngine) verify(ctx context.Context, c *sql.Conn) (*dbscan.ReadOnlyCheck, error) {
	ro := &dbscan.ReadOnlyCheck{}
	var super, createRole, createDB, repl, bypass, dbOwner, dbCreate bool
	err := c.QueryRowContext(ctx, `
SELECT current_user::text, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
       pg_has_role(current_user, d.datdba, 'USAGE'), has_database_privilege(current_database(), 'CREATE')
FROM pg_roles r, pg_database d
WHERE r.rolname = current_user AND d.datname = current_database()`).
		Scan(&ro.User, &super, &createRole, &createDB, &repl, &bypass, &dbOwner, &dbCreate)
	if err != nil {
		return nil, err
	}
	flag := func(on bool, msg string) {
		if on {
			ro.Violations = append(ro.Violations, msg)
		}
	}
	flag(super, "The role is a superuser.")
	flag(createRole, "The role can create roles (CREATEROLE).")
	flag(createDB, "The role can create databases (CREATEDB).")
	flag(repl, "The role has the REPLICATION attribute.")
	flag(bypass, "The role bypasses row-level security (BYPASSRLS).")
	flag(dbOwner, "The role owns this database (or is a member of its owner).")
	flag(dbCreate, "The role can create schemas in this database (CREATE on the database).")

	roles, err := queryStrings(ctx, c, `
SELECT b.rolname::text FROM pg_roles b
WHERE b.rolname IN ('pg_write_all_data', 'pg_write_server_files', 'pg_execute_server_program', 'pg_signal_backend',
                    'pg_checkpoint', 'pg_maintain', 'pg_create_subscription', 'pg_use_reserved_connections')
  AND pg_has_role(current_user, b.oid, 'USAGE')`)
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		ro.Violations = append(ro.Violations, fmt.Sprintf("The role is a member of %s.", role))
	}

	schemas, err := queryStrings(ctx, c, `
SELECT n.nspname::text FROM pg_namespace n
WHERE `+pgUserSchemas+` AND has_schema_privilege(n.oid, 'CREATE') ORDER BY 1 LIMIT 20`)
	if err != nil {
		return nil, err
	}
	for _, s := range schemas {
		ro.Violations = append(ro.Violations, fmt.Sprintf(
			"The role can create objects in schema %q (REVOKE CREATE ON SCHEMA %s FROM PUBLIC / from the role).", s, s))
	}

	owned, err := queryStrings(ctx, c, `
SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND pg_has_role(current_user, c.relowner, 'USAGE')
ORDER BY 1 LIMIT 10`)
	if err != nil {
		return nil, err
	}
	for _, o := range owned {
		ro.Violations = append(ro.Violations, fmt.Sprintf("The role owns %s (owners can alter and drop it).", o))
	}

	writes, err := queryStrings(ctx, c, `
SELECT p.priv || ' on ' || n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('TRIGGER')) AS p(priv)
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND CASE WHEN c.relkind IN ('r', 'p', 'v', 'm', 'f') THEN has_table_privilege(c.oid, p.priv) ELSE false END
ORDER BY 1 LIMIT 25`)
	if err != nil {
		return nil, err
	}
	for _, w := range writes {
		ro.Violations = append(ro.Violations, "Write privilege: "+w+".")
	}

	seqs, err := queryStrings(ctx, c, `
SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind = 'S'
  AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'UPDATE') ELSE false END ORDER BY 1 LIMIT 10`)
	if err != nil {
		return nil, err
	}
	for _, s := range seqs {
		ro.Violations = append(ro.Violations, "UPDATE on sequence "+s+" (can change its value).")
	}

	var readable int
	if err := c.QueryRowContext(ctx, `
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p', 'v', 'm') AND has_table_privilege(c.oid, 'SELECT')`).Scan(&readable); err != nil {
		return nil, err
	}
	ro.Allowed = append(ro.Allowed, fmt.Sprintf("SELECT on %d tables/views", readable), "CONNECT", "session forced read-only")
	var tx string
	if err := c.QueryRowContext(ctx, `SHOW transaction_read_only`).Scan(&tx); err == nil && tx != "on" {
		ro.Violations = append(ro.Violations, "The server did not accept a read-only session.")
	}
	ro.OK = len(ro.Violations) == 0
	return ro, nil
}

func (postgresEngine) snapshot(ctx context.Context, c *sql.Conn, _ Request) (*dbscan.Snapshot, error) {
	s := &dbscan.Snapshot{}
	if err := c.QueryRowContext(ctx, `
SELECT current_database()::text, current_setting('server_version'), d.datcollate::text, pg_encoding_to_char(d.encoding)::text
FROM pg_database d WHERE d.datname = current_database()`).Scan(&s.Database, &s.ServerVersion, &s.Collation, &s.CharSet); err != nil {
		return nil, err
	}

	byKey := map[string]*dbscan.Table{}
	key := func(schema, table string) string { return schema + "\x00" + table }
	err := each(ctx, c, `
SELECT n.nspname::text, c.relname::text, c.reltuples::bigint
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND `+pgNotExtension+`
ORDER BY 1, 2 LIMIT $1`, func(rows *sql.Rows) error {
		var t dbscan.Table
		if err := rows.Scan(&t.Schema, &t.Name, &t.RowEst); err != nil {
			return err
		}
		s.Tables = append(s.Tables, t)
		return nil
	}, MaxTables+1)
	if err != nil {
		return nil, err
	}
	if len(s.Tables) > MaxTables {
		s.Tables, s.Truncated = s.Tables[:MaxTables], true
	}
	for i := range s.Tables {
		byKey[key(s.Tables[i].Schema, s.Tables[i].Name)] = &s.Tables[i]
	}

	err = each(ctx, c, `
SELECT n.nspname::text, c.relname::text, a.attname::text, format_type(a.atttypid, a.atttypmod), t.typname::text,
       NOT a.attnotnull,
       -- identity or serial; the default expression itself never leaves the database
       a.attidentity <> '' OR coalesce(pg_get_expr(d.adbin, d.adrelid), '') LIKE 'nextval(%',
       CASE WHEN t.typname IN ('varchar', 'bpchar') AND a.atttypmod > 4 THEN a.atttypmod - 4 ELSE 0 END,
       coalesce(co.collname::text, '')
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_type t ON t.oid = a.atttypid
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> 0 AND co.collname <> 'default'
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY n.nspname, c.relname, a.attnum`, func(rows *sql.Rows) error {
		var schema, table, typname string
		var col dbscan.Column
		if err := rows.Scan(&schema, &table, &col.Name, &col.FullType, &typname, &col.Nullable,
			&col.Identity, &col.Length, &col.Collation); err != nil {
			return err
		}
		col.DataType = pgType(typname)
		if t := byKey[key(schema, table)]; t != nil {
			t.Columns = append(t.Columns, col)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = each(ctx, c, `
SELECT n.nspname::text, c.relname::text, i.relname::text, ix.indisunique, ix.indisprimary,
       coalesce((SELECT string_agg(a.attname::text, chr(31) ORDER BY k.ord)
                 FROM unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum), '')
FROM pg_index ix
JOIN pg_class c ON c.oid = ix.indrelid JOIN pg_class i ON i.oid = ix.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p')
ORDER BY 1, 2, 3`, func(rows *sql.Rows) error {
		var schema, table, cols string
		var ix dbscan.Index
		if err := rows.Scan(&schema, &table, &ix.Name, &ix.Unique, &ix.Primary, &cols); err != nil {
			return err
		}
		ix.Columns = splitList(cols)
		if t := byKey[key(schema, table)]; t != nil {
			t.Indexes = append(t.Indexes, ix)
			if ix.Primary {
				t.PrimaryKey = ix.Columns
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = each(ctx, c, `
SELECT n.nspname::text, c.relname::text, con.conname::text, rn.nspname::text, rc.relname::text,
       coalesce((SELECT string_agg(a.attname::text, chr(31) ORDER BY k.ord) FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum), ''),
       coalesce((SELECT string_agg(a.attname::text, chr(31) ORDER BY k.ord) FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum), '')
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class rc ON rc.oid = con.confrelid JOIN pg_namespace rn ON rn.oid = rc.relnamespace
WHERE con.contype = 'f' AND `+pgUserSchemas+`
ORDER BY 1, 2, 3`, func(rows *sql.Rows) error {
		var schema, table, cols, refCols string
		var fk dbscan.ForeignKey
		if err := rows.Scan(&schema, &table, &fk.Name, &fk.RefSchema, &fk.RefTable, &cols, &refCols); err != nil {
			return err
		}
		fk.Columns, fk.RefColumns = splitList(cols), splitList(refCols)
		if t := byKey[key(schema, table)]; t != nil {
			t.ForeignKey = append(t.ForeignKey, fk)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Current sequence values behind serial/identity columns (null when
	// the account may not read the sequence; optional).
	_ = each(ctx, c, `
SELECT n.nspname::text, c.relname::text, a.attname::text, s.last_value
FROM pg_depend dep
JOIN pg_class sc ON sc.oid = dep.objid AND sc.relkind = 'S'
JOIN pg_namespace sn ON sn.oid = sc.relnamespace
JOIN pg_class c ON c.oid = dep.refobjid JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = dep.refobjsubid
JOIN pg_sequences s ON s.schemaname = sn.nspname AND s.sequencename = sc.relname
WHERE dep.classid = 'pg_class'::regclass AND dep.deptype IN ('a', 'i') AND s.last_value IS NOT NULL AND `+pgUserSchemas,
		func(rows *sql.Rows) error {
			var schema, table, col string
			var last int64
			if err := rows.Scan(&schema, &table, &col, &last); err != nil {
				return err
			}
			if t := byKey[key(schema, table)]; t != nil {
				for i := range t.Columns {
					if t.Columns[i].Name == col {
						t.Columns[i].IdentityValue = last
					}
				}
			}
			return nil
		})

	err = each(ctx, c, `
SELECT n.nspname::text, c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE `+pgUserSchemas+` AND c.relkind IN ('v', 'm') AND `+pgNotExtension+` ORDER BY 1, 2 LIMIT 5000`, func(rows *sql.Rows) error {
		var v dbscan.View
		if err := rows.Scan(&v.Schema, &v.Name); err != nil {
			return err
		}
		s.Views = append(s.Views, v)
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = each(ctx, c, `
SELECT n.nspname::text, p.proname::text, CASE p.prokind WHEN 'p' THEN 'procedure' ELSE 'function' END
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE `+pgUserSchemas+` AND p.prokind IN ('f', 'p')
  AND NOT EXISTS (SELECT 1 FROM pg_depend dx WHERE dx.classid = 'pg_proc'::regclass AND dx.objid = p.oid AND dx.deptype = 'e')
ORDER BY 1, 2 LIMIT 5000`, func(rows *sql.Rows) error {
		var r dbscan.Routine
		if err := rows.Scan(&r.Schema, &r.Name, &r.Kind); err != nil {
			return err
		}
		s.Routines = append(s.Routines, r)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Privileges granted to PUBLIC (grantee 0 in the ACL); optional.
	_ = each(ctx, c, `
SELECT n.nspname::text, c.relname::text, a.privilege_type::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) AS a
WHERE `+pgUserSchemas+` AND c.relkind IN ('r', 'p', 'v', 'm') AND a.grantee = 0
ORDER BY 1, 2, 3 LIMIT 2000`, func(rows *sql.Rows) error {
		var g dbscan.Grant
		if err := rows.Scan(&g.Schema, &g.Table, &g.Privilege); err != nil {
			return err
		}
		s.PublicGrants = append(s.PublicGrants, g)
		return nil
	})
	return s, nil
}

// pgType maps internal type names to the SQL names used by the rules.
func pgType(t string) string {
	switch t {
	case "int2":
		return "smallint"
	case "int4":
		return "integer"
	case "int8":
		return "bigint"
	case "float4":
		return "real"
	case "float8":
		return "double precision"
	case "bpchar":
		return "char"
	case "bool":
		return "boolean"
	}
	return t
}

func queryStrings(ctx context.Context, c *sql.Conn, q string, args ...any) ([]string, error) {
	rows, err := c.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
