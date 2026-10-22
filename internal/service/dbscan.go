package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/dbscan"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// DBConnAAD binds an encrypted database password to its connection.
func DBConnAAD(id uuid.UUID) []byte { return []byte("dbconn:" + id.String()) }

// DBConnInput creates or edits a database connection.
type DBConnInput struct {
	Name            string
	Engine          string
	Host            string
	Port            int
	Database        string
	User            string
	Password        string // empty on edit = keep the stored one
	TLS             string
	Schedule        string
	ScheduleHour    int
	ScheduleWeekday int
	Exclude         []string
}

func (in *DBConnInput) validate(creating bool) error {
	name, err := cleanName("name", in.Name, 1, 100)
	if err != nil {
		return err
	}
	in.Name = name
	if !dbscan.ValidEngine(in.Engine) {
		return invalid("engine", "invalid")
	}
	in.Host = strings.TrimSpace(in.Host)
	in.Host = strings.TrimSuffix(strings.TrimPrefix(in.Host, "["), "]")
	if in.Host == "" || len(in.Host) > 253 || strings.ContainsAny(in.Host, " /\\@?#'\"`;,") {
		return invalid("host", "invalid")
	}
	if ip := net.ParseIP(in.Host); ip == nil {
		for _, label := range strings.Split(in.Host, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") {
				return invalid("host", "invalid")
			}
		}
	}
	if in.Port == 0 {
		in.Port = dbscan.DefaultPort(in.Engine)
	}
	if in.Port < 1 || in.Port > 65535 {
		return invalid("port", "invalid")
	}
	in.Database = strings.TrimSpace(in.Database)
	if in.Database == "" || len(in.Database) > 128 {
		return invalid("database", "invalid")
	}
	in.User = strings.TrimSpace(in.User)
	if in.User == "" || len(in.User) > 128 {
		return invalid("user", "invalid")
	}
	if len(in.Password) > 1024 || (creating && in.Password == "") {
		return invalid("password", "required")
	}
	switch in.TLS {
	case "":
		in.TLS = "require"
	case "disable", "require", "verify":
	default:
		return invalid("tls", "invalid")
	}
	if in.Schedule == "" {
		in.Schedule = dbscan.ScheduleOff
	}
	if !dbscan.ValidSchedule(in.Schedule) || in.ScheduleHour < 0 || in.ScheduleHour > 23 || in.ScheduleWeekday < 0 || in.ScheduleWeekday > 6 {
		return invalid("schedule", "invalid")
	}
	var ex []string
	for _, e := range in.Exclude {
		if e = strings.TrimSpace(e); e != "" {
			if len(e) > 200 {
				return invalid("exclude", "invalid")
			}
			ex = append(ex, e)
		}
	}
	if len(ex) > 100 {
		return invalid("exclude", "too_many")
	}
	in.Exclude = ex
	return nil
}

// VerifyResult is the stored outcome of the last read-only check.
type VerifyResult struct {
	Code     string                `json:"code,omitempty"`
	Error    string                `json:"error,omitempty"`
	ReadOnly *dbscan.ReadOnlyCheck `json:"read_only,omitempty"`
	Server   string                `json:"server,omitempty"`
}

// ParseVerify decodes db_connections.verify_result.
func ParseVerify(raw json.RawMessage) VerifyResult {
	var v VerifyResult
	_ = json.Unmarshal(raw, &v)
	return v
}

// instanceLocation is the instance time zone (schedules).
func (s *Service) instanceLocation(ctx context.Context) *time.Location {
	inst, err := s.Instance(ctx)
	if err == nil && inst.Timezone != "" {
		if loc, err := time.LoadLocation(inst.Timezone); err == nil {
			return loc
		}
	}
	return time.UTC
}

// CreateDBConnection stores a connection; the worker then checks right
// away that the account is read-only (a write-capable account is
// rejected and its password deleted).
func (s *Service) CreateDBConnection(ctx context.Context, o *OrgCtx, in DBConnInput, m Meta) (*db.DbConnection, error) {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	mod, err := s.requireModuleWrite(ctx, o, ModuleDB)
	if err != nil {
		return nil, err
	}
	if err := in.validate(true); err != nil {
		return nil, err
	}
	if mod.Settings.NoSchedule {
		in.Schedule = dbscan.ScheduleOff
	}
	id := newID()
	enc, nonce, err := s.box.Seal([]byte(in.Password), DBConnAAD(id))
	if err != nil {
		return nil, err
	}
	next := dbscan.NextRun(in.Schedule, in.ScheduleHour, in.ScheduleWeekday, time.Now(), s.instanceLocation(ctx))
	var c db.DbConnection
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if mod.Settings.MaxItems > 0 {
			n, err := q.CountDBConnections(ctx, o.Org.ID)
			if err != nil {
				return err
			}
			if n >= int64(mod.Settings.MaxItems) {
				return invalid("name", "limit")
			}
		}
		var err error
		c, err = q.CreateDBConnection(ctx, db.CreateDBConnectionParams{
			ID: id, OrgID: o.Org.ID, Name: in.Name, Engine: in.Engine, Host: in.Host, Port: int32(in.Port), //nolint:gosec // validated
			DatabaseName: in.Database, Username: in.User, PasswordEnc: enc, PasswordNonce: nonce, TlsMode: in.TLS,
			Schedule: in.Schedule, ScheduleHour: int32(in.ScheduleHour), ScheduleWeekday: int32(in.ScheduleWeekday), //nolint:gosec // validated
			NextRunAt: next, Exclude: in.Exclude, CreatedBy: &o.P.UserID,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return invalid("name", "taken")
			}
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "db.connection_created", "db_connection", c.ID.String(), m,
			map[string]any{"name": c.Name, "engine": c.Engine, "host": c.Host, "database": c.DatabaseName, "user": c.Username})
	})
	if err != nil {
		return nil, wrap("create db connection", err)
	}
	return &c, nil
}

// UpdateDBConnection edits a connection. Changing where the credential is
// sent (engine, host, port, database, user) requires the password again,
// so a stored password can never be redirected to another server; any new
// target or password is checked again before use.
func (s *Service) UpdateDBConnection(ctx context.Context, o *OrgCtx, id string, in DBConnInput, m Meta) (*db.DbConnection, error) {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	mod, err := s.requireModuleWrite(ctx, o, ModuleDB)
	if err != nil {
		return nil, err
	}
	cid, err := parseID(id)
	if err != nil {
		return nil, err
	}
	if err := in.validate(false); err != nil {
		return nil, err
	}
	if mod.Settings.NoSchedule {
		in.Schedule = dbscan.ScheduleOff
	}
	next := dbscan.NextRun(in.Schedule, in.ScheduleHour, in.ScheduleWeekday, time.Now(), s.instanceLocation(ctx))
	var c db.DbConnection
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		cur, err := q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: o.Org.ID, ID: cid})
		if err != nil {
			return store.NotFound(err)
		}
		targetChanged := cur.Engine != in.Engine || !strings.EqualFold(cur.Host, in.Host) || int(cur.Port) != in.Port ||
			cur.DatabaseName != in.Database || cur.Username != in.User
		if (targetChanged || cur.PasswordEnc == nil) && in.Password == "" {
			return invalid("password", "required_for_target")
		}
		c, err = q.UpdateDBConnection(ctx, db.UpdateDBConnectionParams{
			OrgID: o.Org.ID, ID: cid, Name: in.Name, TlsMode: in.TLS, Schedule: in.Schedule,
			ScheduleHour: int32(in.ScheduleHour), ScheduleWeekday: int32(in.ScheduleWeekday), NextRunAt: next, //nolint:gosec // validated
			Exclude: in.Exclude,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return invalid("name", "taken")
			}
			return err
		}
		if targetChanged || in.Password != "" || cur.TlsMode != in.TLS {
			enc, nonce := cur.PasswordEnc, cur.PasswordNonce
			if in.Password != "" {
				if enc, nonce, err = s.box.Seal([]byte(in.Password), DBConnAAD(cid)); err != nil {
					return err
				}
			}
			c, err = q.SetDBConnectionTarget(ctx, db.SetDBConnectionTargetParams{
				OrgID: o.Org.ID, ID: cid, Engine: in.Engine, Host: in.Host, Port: int32(in.Port), //nolint:gosec // validated
				DatabaseName: in.Database, Username: in.User, PasswordEnc: enc, PasswordNonce: nonce,
			})
			if err != nil {
				return err
			}
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "db.connection_updated", "db_connection", c.ID.String(), m,
			map[string]any{"name": c.Name, "target_changed": targetChanged, "password_changed": in.Password != ""})
	})
	if err != nil {
		return nil, wrap("update db connection", err)
	}
	return &c, nil
}

// DeleteDBConnection removes a connection with its scans.
func (s *Service) DeleteDBConnection(ctx context.Context, o *OrgCtx, id string, m Meta) error {
	if err := o.Require(auth.ActProjectDelete, "write"); err != nil {
		return err
	}
	cid, err := parseID(id)
	if err != nil {
		return err
	}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		c, err := q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: o.Org.ID, ID: cid})
		if err != nil {
			return store.NotFound(err)
		}
		if _, err := q.DeleteDBConnection(ctx, db.DeleteDBConnectionParams{OrgID: o.Org.ID, ID: cid}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "db.connection_deleted", "db_connection", cid.String(), m,
			map[string]any{"name": c.Name})
	})
	return wrap("delete db connection", err)
}

// VerifyDBConnection queues a new read-only check.
func (s *Service) VerifyDBConnection(ctx context.Context, o *OrgCtx, id string) error {
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return err
	}
	cid, err := parseID(id)
	if err != nil {
		return err
	}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		return q.RequestDBVerify(ctx, db.RequestDBVerifyParams{OrgID: o.Org.ID, ID: cid})
	})
	return wrap("verify db connection", err)
}

// DBConnView is a connection with its latest scan.
type DBConnView struct {
	Conn   db.DbConnection
	Verify VerifyResult
	Last   *db.LastDBScanPerConnectionRow
}

// ListDBConnections lists the org's connections.
func (s *Service) ListDBConnections(ctx context.Context, o *OrgCtx) ([]DBConnView, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return nil, err
	}
	var out []DBConnView
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		conns, err := q.ListDBConnections(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		last, err := q.LastDBScanPerConnection(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		byConn := map[uuid.UUID]*db.LastDBScanPerConnectionRow{}
		for i := range last {
			byConn[last[i].ConnectionID] = &last[i]
		}
		for _, c := range conns {
			out = append(out, DBConnView{Conn: c, Verify: ParseVerify(c.VerifyResult), Last: byConn[c.ID]})
		}
		return nil
	})
	return out, wrap("list db connections", err)
}

// DBConnDetail is a connection with its scan history.
type DBConnDetail struct {
	DBConnView
	Scans  []db.ListDBScansRow
	Active *db.DbScan
}

// GetDBConnection returns a connection with its recent scans.
func (s *Service) GetDBConnection(ctx context.Context, o *OrgCtx, id string) (*DBConnDetail, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return nil, err
	}
	cid, err := parseID(id)
	if err != nil {
		return nil, err
	}
	out := &DBConnDetail{}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		c, err := q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: o.Org.ID, ID: cid})
		if err != nil {
			return store.NotFound(err)
		}
		out.Conn, out.Verify = c, ParseVerify(c.VerifyResult)
		if out.Scans, err = q.ListDBScans(ctx, db.ListDBScansParams{OrgID: o.Org.ID, ConnectionID: cid, Limit: 50}); err != nil {
			return err
		}
		if a, err := q.ActiveDBScan(ctx, cid); err == nil {
			out.Active = &a
		}
		return nil
	})
	if err != nil {
		return nil, wrap("get db connection", err)
	}
	return out, nil
}

// ErrNotReady means the connection's account has not passed the read-only check.
var ErrNotReady = errors.New("not_ready")

// TriggerDBScan queues a scan (or returns the one already queued/running).
func (s *Service) TriggerDBScan(ctx context.Context, o *OrgCtx, id string, m Meta) (*db.DbScan, error) {
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return nil, err
	}
	cid, err := parseID(id)
	if err != nil {
		return nil, err
	}
	var sc db.DbScan
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		c, err := q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: o.Org.ID, ID: cid})
		if err != nil {
			return store.NotFound(err)
		}
		if c.Status != "ready" {
			return ErrNotReady
		}
		sc, err = q.CreateDBScan(ctx, db.CreateDBScanParams{ID: newID(), OrgID: o.Org.ID, ConnectionID: cid, Trigger: "manual", TriggeredBy: &o.P.UserID})
		if err != nil {
			if !store.IsNoRows(err) {
				return err
			}
			if sc, err = q.ActiveDBScan(ctx, cid); err != nil {
				return err
			}
			return nil
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "db.scan_triggered", "db_scan", sc.ID.String(), m, map[string]any{"connection": c.Name})
	})
	if err != nil {
		return nil, wrap("trigger db scan", err)
	}
	return &sc, nil
}

// CancelDBScan cancels a queued scan.
func (s *Service) CancelDBScan(ctx context.Context, o *OrgCtx, id string) error {
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return err
	}
	sid, err := parseID(id)
	if err != nil {
		return err
	}
	return wrap("cancel db scan", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		n, err := q.CancelDBScan(ctx, db.CancelDBScanParams{OrgID: o.Org.ID, ID: sid})
		if err == nil && n == 0 {
			return ErrConflict
		}
		return err
	}))
}

// DBScanSummary is db_scans.summary.
type DBScanSummary struct {
	Stats      dbscan.Stats           `json:"stats"`
	Categories []dbscan.CategoryScore `json:"categories"`
	Checked    map[string]int         `json:"checked"`
	Server     string                 `json:"server"`
	Database   string                 `json:"database"`
	Duration   int64                  `json:"duration_ms"`
	FailOn     string                 `json:"fail_on"`
}

// DBFindingView is a finding with its new flag.
type DBFindingView struct {
	dbscan.Finding
	IsNew bool
}

// DBScanView is a scan report.
type DBScanView struct {
	Scan     db.DbScan
	Conn     db.DbConnection
	Summary  DBScanSummary
	Counts   map[string]int
	ReadOnly *dbscan.ReadOnlyCheck
	Findings []DBFindingView
}

// GetDBScan returns a scan with its findings.
func (s *Service) GetDBScan(ctx context.Context, o *OrgCtx, id string) (*DBScanView, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return nil, err
	}
	sid, err := parseID(id)
	if err != nil {
		return nil, err
	}
	out := &DBScanView{}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		sc, err := q.GetDBScan(ctx, db.GetDBScanParams{OrgID: o.Org.ID, ID: sid})
		if err != nil {
			return store.NotFound(err)
		}
		out.Scan = sc
		if out.Conn, err = q.GetDBConnection(ctx, db.GetDBConnectionParams{OrgID: o.Org.ID, ID: sc.ConnectionID}); err != nil {
			return store.NotFound(err)
		}
		_ = json.Unmarshal(sc.Summary, &out.Summary)
		_ = json.Unmarshal(sc.Counts, &out.Counts)
		var ro dbscan.ReadOnlyCheck
		if json.Unmarshal(sc.ReadOnly, &ro) == nil && ro.User != "" {
			out.ReadOnly = &ro
		}
		rows, err := q.ListDBFindings(ctx, db.ListDBFindingsParams{OrgID: o.Org.ID, ScanID: sid})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Findings = append(out.Findings, DBFindingView{IsNew: r.IsNew, Finding: dbscan.Finding{
				RuleID: r.RuleID, Category: r.Category, Severity: r.Severity, ObjectType: r.ObjectType, Object: r.Object,
				Params: r.Params, Details: r.Details, Fingerprint: r.Fingerprint,
			}})
		}
		return nil
	})
	if err != nil {
		return nil, wrap("get db scan", err)
	}
	sortDBFindings(out.Findings)
	return out, nil
}

func sortDBFindings(fs []DBFindingView) {
	less := func(a, b *DBFindingView) bool {
		if dbscan.SevRank(a.Severity) != dbscan.SevRank(b.Severity) {
			return dbscan.SevRank(a.Severity) > dbscan.SevRank(b.Severity)
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Object < b.Object
	}
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && less(&fs[j], &fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

// DBProfile returns the org's rule profile (as stored, defaults not filled).
func (s *Service) DBProfile(ctx context.Context, o *OrgCtx) (dbscan.Profile, error) {
	var p dbscan.Profile
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return p, err
	}
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		row, err := q.GetDBProfile(ctx, o.Org.ID)
		if err != nil {
			if store.IsNoRows(err) {
				return nil
			}
			return err
		}
		return json.Unmarshal(row.Profile, &p)
	})
	return p, wrap("db profile", err)
}

// SaveDBProfile stores the org's rule profile (admins).
func (s *Service) SaveDBProfile(ctx context.Context, o *OrgCtx, p dbscan.Profile, m Meta) error {
	if err := o.Require(auth.ActOrgUpdate, "write"); err != nil {
		return err
	}
	if err := s.RequireModule(ctx, o, ModuleDB); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return invalid("profile", err.Error())
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return wrap("save db profile", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.UpsertDBProfile(ctx, db.UpsertDBProfileParams{OrgID: o.Org.ID, Profile: raw, UpdatedBy: &o.P.UserID}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "db.profile_updated", "org", o.Org.ID.String(), m, nil)
	}))
}
