// Package dbscan is scanX's database module: it inspects the structure of
// PostgreSQL, MySQL/MariaDB and SQL Server databases through a read-only
// account and checks it against naming, consistency, structure and
// security rules.
//
// Only catalog metadata is read (names, types, keys, indexes, row-count
// estimates and grants); table contents are never queried. The inspection
// runs in a throw-away sandbox container (see package inspect); the rules
// run in the worker on the resulting Snapshot.
package dbscan

import "time"

// Engines.
const (
	EnginePostgres = "postgres"
	EngineMySQL    = "mysql"
	EngineMSSQL    = "mssql"
)

// ValidEngine reports whether e is supported.
func ValidEngine(e string) bool {
	return e == EnginePostgres || e == EngineMySQL || e == EngineMSSQL
}

// DefaultPort is the usual port of an engine.
func DefaultPort(engine string) int {
	switch engine {
	case EngineMySQL:
		return 3306
	case EngineMSSQL:
		return 1433
	}
	return 5432
}

// Snapshot is the structure of one database.
type Snapshot struct {
	Engine        string    `json:"engine"`
	ServerVersion string    `json:"server_version"`
	Database      string    `json:"database"`
	Collation     string    `json:"collation,omitempty"`
	CharSet       string    `json:"charset,omitempty"`
	TakenAt       time.Time `json:"taken_at"`
	Tables        []Table   `json:"tables"`
	Views         []View    `json:"views"`
	Routines      []Routine `json:"routines,omitempty"`
	// PublicGrants are table privileges granted to everyone (PUBLIC).
	PublicGrants []Grant `json:"public_grants,omitempty"`
	// Truncated is set when the database had more objects than scanX
	// inspects in one run.
	Truncated bool `json:"truncated,omitempty"`
}

// Table is a base table.
type Table struct {
	Schema     string       `json:"schema"`
	Name       string       `json:"name"`
	Columns    []Column     `json:"columns"`
	PrimaryKey []string     `json:"primary_key,omitempty"`
	ForeignKey []ForeignKey `json:"foreign_keys,omitempty"`
	Indexes    []Index      `json:"indexes,omitempty"`
	RowEst     int64        `json:"row_estimate"`
	// Storage engine (MySQL: InnoDB, MyISAM...).
	StorageEngine string `json:"storage_engine,omitempty"`
	Collation     string `json:"collation,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// QualifiedName is schema.name (name alone when there is no schema).
func (t *Table) QualifiedName() string {
	if t.Schema == "" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

// Column is a table column.
type Column struct {
	Name     string `json:"name"`
	DataType string `json:"data_type"` // base type, lower case: varchar, int, timestamptz...
	FullType string `json:"full_type"` // with length/precision: varchar(100)
	Length   int    `json:"length,omitempty"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
	Identity bool   `json:"identity,omitempty"`
	// IdentityValue is the current identity/auto-increment/sequence value
	// when the catalog exposes it (overflow check); 0 = unknown.
	IdentityValue int64  `json:"identity_value,omitempty"`
	Collation     string `json:"collation,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// ForeignKey is a foreign-key constraint.
type ForeignKey struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns"`
	RefSchema  string   `json:"ref_schema"`
	RefTable   string   `json:"ref_table"`
	RefColumns []string `json:"ref_columns"`
}

// Index is an index (including the ones backing PK/unique constraints).
type Index struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
	Primary bool     `json:"primary"`
}

// View is a view (definitions are not stored).
type View struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
}

// Routine is a stored procedure or function (name only).
type Routine struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // procedure | function
}

// Grant is a privilege on a table.
type Grant struct {
	Schema    string `json:"schema"`
	Table     string `json:"table"`
	Privilege string `json:"privilege"`
}

// ReadOnlyCheck is the result of verifying that an account cannot write.
type ReadOnlyCheck struct {
	OK bool `json:"ok"`
	// User is the account as the server sees it.
	User string `json:"user"`
	// Allowed lists the privileges found that are compatible with a
	// read-only account (shown to the user as evidence).
	Allowed []string `json:"allowed,omitempty"`
	// Violations explain every write/admin capability found.
	Violations []string `json:"violations,omitempty"`
	// Warnings do not block (e.g. EXECUTE on procedures).
	Warnings []string `json:"warnings,omitempty"`
}

// ColumnCount is the number of columns in the snapshot.
func (s *Snapshot) ColumnCount() int {
	n := 0
	for i := range s.Tables {
		n += len(s.Tables[i].Columns)
	}
	return n
}
