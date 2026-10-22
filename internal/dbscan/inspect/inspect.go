// Package inspect implements `scanx db-inspect`. It runs inside a
// throw-away sandbox container that can reach the network but not scanX's
// own services, connects to one database with the credentials passed in
// the environment, and prints one result line on stdout:
//
//	SCANX_DBRESULT <base64(gzip(json Result))>
//
// Mode "verify" only checks the account; mode "inspect" checks it again
// and, if it is still read-only, reads the catalog into a Snapshot. Every
// query is a catalog read: no table contents are ever selected. Sessions
// are read-only where the engine supports it (PostgreSQL, MySQL).
package inspect

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/dbscan"
)

// Modes.
const (
	ModeVerify  = "verify"
	ModeInspect = "inspect"

	// ResultPrefix starts the result line on stdout.
	ResultPrefix = "SCANX_DBRESULT "

	// MaxTables bounds one inspection (the snapshot is marked truncated).
	MaxTables = 5000
)

// TLS modes.
const (
	TLSDisable = "disable" // plain connection
	TLSRequire = "require" // encrypted, certificate not verified
	TLSVerify  = "verify"  // encrypted, certificate and host name verified
)

// Request is read from the environment (never from argv, so the password
// does not show up in process listings).
type Request struct {
	Mode     string
	Engine   string
	Host     string
	Port     int
	Database string
	User     string
	Password string
	TLS      string
}

// Result is the JSON payload of the result line.
type Result struct {
	OK       bool                  `json:"ok"`
	Code     string                `json:"code,omitempty"` // connect | auth | database | tls | blocked | not_readonly | query | request
	Error    string                `json:"error,omitempty"`
	ReadOnly *dbscan.ReadOnlyCheck `json:"read_only,omitempty"`
	Snapshot *dbscan.Snapshot      `json:"snapshot,omitempty"`
	Duration int64                 `json:"duration_ms"`
}

// RequestFromEnv reads SCANX_DB_*.
func RequestFromEnv() (Request, error) {
	port, _ := strconv.Atoi(os.Getenv("SCANX_DB_PORT"))
	r := Request{
		Mode: os.Getenv("SCANX_DB_MODE"), Engine: os.Getenv("SCANX_DB_ENGINE"), Host: os.Getenv("SCANX_DB_HOST"),
		Port: port, Database: os.Getenv("SCANX_DB_NAME"), User: os.Getenv("SCANX_DB_USER"), TLS: os.Getenv("SCANX_DB_TLS"),
	}
	if p := os.Getenv("SCANX_DB_PASSWORD_B64"); p != "" {
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return r, errors.New("password is not valid base64")
		}
		r.Password = string(b)
	}
	if r.Mode != ModeVerify && r.Mode != ModeInspect {
		return r, errors.New("unknown mode")
	}
	if !dbscan.ValidEngine(r.Engine) || r.Host == "" || r.User == "" || r.Port <= 0 || r.Port > 65535 {
		return r, errors.New("incomplete connection settings")
	}
	if r.TLS == "" {
		r.TLS = TLSRequire
	}
	return r, nil
}

// Main is the entry point of `scanx db-inspect`.
func Main(ctx context.Context, stdout, _ io.Writer) int {
	req, err := RequestFromEnv()
	var res Result
	if err != nil {
		res = Result{Code: "request", Error: err.Error()}
	} else {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		res = Run(ctx, req)
	}
	line, err := Encode(&res)
	if err != nil {
		return 1
	}
	_, _ = fmt.Fprintln(stdout, ResultPrefix+line)
	return 0
}

// Encode gzips and base64-encodes a result.
func Encode(r *Result) (string, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if err := json.NewEncoder(zw).Encode(r); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// Decode finds the result line in a container's stdout.
func Decode(stdout []byte) (*Result, error) {
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ResultPrefix) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, ResultPrefix))
		if err != nil {
			return nil, err
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		var r Result
		if err := json.NewDecoder(io.LimitReader(zr, 256<<20)).Decode(&r); err != nil {
			return nil, err
		}
		return &r, nil
	}
	return nil, errors.New("no result in the inspector output")
}

// engine is one database flavour.
type engine interface {
	// open connects and returns one connection with the session set up
	// (read-only where possible, short lock/statement timeouts).
	open(ctx context.Context, r Request) (*sql.DB, *sql.Conn, error)
	verify(ctx context.Context, c *sql.Conn) (*dbscan.ReadOnlyCheck, error)
	snapshot(ctx context.Context, c *sql.Conn, r Request) (*dbscan.Snapshot, error)
}

func engineFor(name string) engine {
	switch name {
	case dbscan.EngineMySQL:
		return mysqlEngine{}
	case dbscan.EngineMSSQL:
		return mssqlEngine{}
	}
	return postgresEngine{}
}

// Run verifies the account and, in inspect mode, reads the structure.
func Run(ctx context.Context, r Request) Result {
	start := time.Now()
	res := run(ctx, r)
	res.Duration = time.Since(start).Milliseconds()
	if res.Error != "" && r.Password != "" {
		res.Error = strings.ReplaceAll(res.Error, r.Password, "***")
	}
	return res
}

func run(ctx context.Context, r Request) Result {
	if err := checkHost(ctx, r.Host); err != nil {
		return Result{Code: "blocked", Error: err.Error()}
	}
	e := engineFor(r.Engine)
	db, conn, err := e.open(ctx, r)
	if err != nil {
		code, msg := classify(err)
		return Result{Code: code, Error: msg}
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	ro, err := e.verify(ctx, conn)
	if err != nil {
		return Result{Code: "query", Error: "Could not read the account's privileges: " + firstLine(err.Error())}
	}
	if !ro.OK {
		return Result{Code: "not_readonly", Error: "The account can change the database.", ReadOnly: ro}
	}
	if r.Mode == ModeVerify {
		return Result{OK: true, ReadOnly: ro}
	}
	snap, err := e.snapshot(ctx, conn, r)
	if err != nil {
		return Result{Code: "query", Error: "Could not read the database structure: " + firstLine(err.Error()), ReadOnly: ro}
	}
	snap.Engine, snap.TakenAt = r.Engine, time.Now().UTC()
	if snap.Database == "" {
		snap.Database = r.Database
	}
	return Result{OK: true, ReadOnly: ro, Snapshot: snap}
}

// checkHost refuses loopback, link-local (cloud metadata) and other
// non-routable targets. Private networks are allowed: databases usually
// live there, and the sandbox network cannot reach scanX's own services.
func checkHost(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve %s", host)
	}
	for _, ip := range ips {
		if Blocked(ip) {
			return fmt.Errorf("%s resolves to %s, which scanX does not connect to (loopback/link-local)", host, ip)
		}
	}
	return nil
}

// Blocked reports addresses the inspector never connects to.
func Blocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	v4 := ip.To4()
	return v4 != nil && v4[0] == 0
}

// classify turns a driver error into a code and a readable message.
func classify(err error) (string, string) {
	msg := firstLine(err.Error())
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "password authentication failed"), strings.Contains(l, "access denied"),
		strings.Contains(l, "login failed"), strings.Contains(l, "authentication"):
		return "auth", "Login failed: check the user name and password. (" + msg + ")"
	case strings.Contains(l, "does not exist") && strings.Contains(l, "database"), strings.Contains(l, "unknown database"),
		strings.Contains(l, "cannot open database"):
		return "database", "The database was not found or the account cannot open it. (" + msg + ")"
	case strings.Contains(l, "tls"), strings.Contains(l, "ssl"), strings.Contains(l, "x509"), strings.Contains(l, "certificate"):
		return "tls", "The encrypted connection failed; check the TLS setting. (" + msg + ")"
	}
	return "connect", "Cannot connect to the database server. (" + msg + ")"
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

// splitList splits an aggregated name list (unit separator).
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x1f")
}

// each runs a query and calls fn for every row; the rows are always closed.
func each(ctx context.Context, c *sql.Conn, q string, fn func(*sql.Rows) error, args ...any) error {
	rows, err := c.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// openConn opens a pool limited to one connection and takes it.
func openConn(ctx context.Context, driver, dsn string, setup ...string) (*sql.DB, *sql.Conn, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := db.Conn(cctx)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	for _, q := range setup {
		if _, err := conn.ExecContext(cctx, q); err != nil {
			_ = conn.Close()
			_ = db.Close()
			return nil, nil, err
		}
	}
	return db, conn, nil
}
