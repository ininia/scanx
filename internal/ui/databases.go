package ui

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/dbscan"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
)

// DBMessage renders a finding's translated message.
func (p *Page) DBMessage(f *dbscan.Finding) string {
	args := make([]any, 0, len(f.Params))
	for i, a := range f.Params {
		switch {
		case f.RuleID == "DBN004":
			a = p.T("dbnum." + a)
		case f.RuleID == "DBS010":
			var parts []string
			for _, c := range strings.Split(a, ", ") {
				parts = append(parts, p.T("dbconcept."+c))
			}
			a = strings.Join(parts, ", ")
		case f.RuleID == "DBC004" && i < 2:
			a = strings.ReplaceAll(a, "<table>", p.T("db.table_placeholder"))
		}
		args = append(args, a)
	}
	msg := p.T("dbrule."+f.RuleID+".msg", args...)
	if strings.Contains(msg, "%!") { // parameter count mismatch: fall back to the title
		return p.T("dbrule." + f.RuleID + ".title")
	}
	return msg
}

// DBObject is the display name of a finding's object.
func (p *Page) DBObject(f *dbscan.Finding) string {
	if f.ObjectType == "concept" {
		return p.T("dbconcept." + f.Object)
	}
	return f.Object
}

// EngineLabel is the product name of an engine.
func EngineLabel(e string) string {
	switch e {
	case dbscan.EngineMySQL:
		return "MySQL / MariaDB"
	case dbscan.EngineMSSQL:
		return "SQL Server"
	}
	return "PostgreSQL"
}

// ConnStatusClass styles a connection status badge.
func ConnStatusClass(status string) string {
	switch status {
	case "ready":
		return "sbadge ok"
	case "rejected", "error":
		return "sbadge bad"
	case "pending", "verifying":
		return "sbadge run"
	}
	return "sbadge off"
}

// ConnBusy reports a connection whose check is still running.
func ConnBusy(status string) bool { return status == "pending" || status == "verifying" }

// DBScanBusy reports a queued or running scan.
func DBScanBusy(status string) bool { return status == "queued" || status == "running" }

// ScoreOf returns a scan score (nil = 0, shown as "—" by callers).
func ScoreOf(s *int32) int {
	if s == nil {
		return 0
	}
	return int(*s)
}

// CountsOf decodes a counts JSON column.
func CountsOf(raw []byte) map[string]int {
	m := map[string]int{}
	_ = json.Unmarshal(raw, &m)
	return m
}

// ScheduleText describes a connection schedule.
func (p *Page) ScheduleText(c *db.DbConnection) string {
	h := strconv.Itoa(int(c.ScheduleHour))
	if len(h) == 1 {
		h = "0" + h
	}
	switch c.Schedule {
	case dbscan.ScheduleHourly:
		return p.T("db.schedule.hourly")
	case dbscan.ScheduleDaily:
		return p.T("db.schedule.daily_at", h+":00")
	case dbscan.ScheduleWeekly:
		return p.T("db.schedule.weekly_at", p.T("weekday."+strconv.Itoa(int(c.ScheduleWeekday))), h+":00")
	}
	return p.T("db.schedule.off")
}

// NextRunText formats the next scheduled run.
func (p *Page) NextRunText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// DBFilter narrows the findings of a scan report.
type DBFilter struct {
	Sev, Cat, Rule, Q string
	New               bool
}

func (f DBFilter) match(x *service.DBFindingView) bool {
	if f.Sev != "" && x.Severity != f.Sev || f.Cat != "" && x.Category != f.Cat || f.Rule != "" && x.RuleID != f.Rule {
		return false
	}
	if f.New && !x.IsNew {
		return false
	}
	if f.Q != "" && !strings.Contains(strings.ToLower(x.Object), strings.ToLower(f.Q)) {
		return false
	}
	return true
}

// Active reports whether any filter is set.
func (f DBFilter) Active() bool {
	return f.Sev != "" || f.Cat != "" || f.Rule != "" || f.New || f.Q != ""
}

// Toggle returns the report URL with one filter switched.
func (f DBFilter) Toggle(base, key, val string) string {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	vals := map[string]string{"sev": f.Sev, "cat": f.Cat, "rule": f.Rule, "q": f.Q}
	if f.New {
		vals["new"] = "1"
	}
	if vals[key] == val {
		vals[key] = ""
	} else {
		vals[key] = val
	}
	for k, v := range vals {
		set(k, v)
	}
	if len(q) == 0 {
		return base
	}
	return base + "?" + q.Encode()
}

// DBRuleGroup is the findings of one rule.
type DBRuleGroup struct {
	Rule     *dbscan.RuleInfo
	Severity string
	New      int
	Findings []service.DBFindingView
}

// DBGroups groups the filtered findings by rule, worst severity first.
func DBGroups(v *service.DBScanView, f DBFilter) []DBRuleGroup {
	var out []DBRuleGroup
	idx := map[string]int{}
	for i := range v.Findings {
		x := v.Findings[i]
		if !f.match(&x) {
			continue
		}
		j, ok := idx[x.RuleID]
		if !ok {
			r := dbscan.RuleByID(x.RuleID)
			if r == nil {
				r = &dbscan.RuleInfo{ID: x.RuleID, Category: x.Category, Severity: x.Severity}
			}
			out = append(out, DBRuleGroup{Rule: r, Severity: x.Severity})
			j = len(out) - 1
			idx[x.RuleID] = j
		}
		g := &out[j]
		if dbscan.SevRank(x.Severity) > dbscan.SevRank(g.Severity) {
			g.Severity = x.Severity
		}
		if x.IsNew {
			g.New++
		}
		g.Findings = append(g.Findings, x)
	}
	return out
}

// DBFacet counts findings per value of a field (all findings) and links
// each value to the report filtered by it.
func DBFacet(v *service.DBScanView, field, base string, f DBFilter) []Facet {
	cur := map[string]string{"sev": f.Sev, "cat": f.Cat, "rule": f.Rule}[field]
	mk := func(val string, n int) Facet {
		return Facet{Dim: field, Value: val, Count: n, Active: cur == val, URL: f.Toggle(base, field, val)}
	}
	count := map[string]int{}
	var order []string
	for _, x := range v.Findings {
		var k string
		switch field {
		case "sev":
			k = x.Severity
		case "cat":
			k = x.Category
		case "rule":
			k = x.RuleID
		}
		if _, ok := count[k]; !ok {
			order = append(order, k)
		}
		count[k]++
	}
	var out []Facet
	switch field {
	case "sev":
		for _, s := range []string{"critical", "high", "medium", "low", "info"} {
			if count[s] > 0 {
				out = append(out, mk(s, count[s]))
			}
		}
	case "cat":
		for _, c := range dbscan.Categories {
			if count[c.ID] > 0 {
				out = append(out, mk(c.ID, count[c.ID]))
			}
		}
	default:
		for _, k := range order {
			out = append(out, mk(k, count[k]))
		}
	}
	return out
}

// MaxShown caps the objects listed per rule group before "show more".
const MaxShown = 50

// FirstN returns at most n findings.
func FirstN(fs []service.DBFindingView, n int) []service.DBFindingView {
	if len(fs) > n {
		return fs[:n]
	}
	return fs
}

// RuleSetting returns a rule's current state in a profile.
func RuleSetting(prof dbscan.Profile, r *dbscan.RuleInfo) (bool, string) { return prof.RuleOn(r) }

// ProfileValue returns a profile option for the rules form (defaults filled).
func ProfileValue(prof dbscan.Profile, key string) string {
	e := prof.Effective()
	switch key {
	case "language":
		return e.Language
	case "table_case":
		return e.TableCase
	case "column_case":
		return e.ColumnCase
	case "table_number":
		return e.TableNumber
	case "max_name_length":
		return strconv.Itoa(e.MaxNameLength)
	case "max_columns":
		return strconv.Itoa(e.MaxColumns)
	case "fail_on":
		return e.FailOn
	case "exclude":
		return strings.Join(prof.Exclude, "\n")
	}
	if c, ok := strings.CutPrefix(key, "audit_"); ok {
		return prof.AuditNames[c]
	}
	return ""
}

// RequireAudit reports the audit-columns option (default on).
func RequireAudit(prof dbscan.Profile) bool { return *prof.Effective().RequireAudit }

// Itoa is strconv.Itoa for templates.
func Itoa(n int) string { return strconv.Itoa(n) }

// roSQL creates a least-privilege account for scanX on an engine.
func roSQL(engine string) string {
	switch engine {
	case dbscan.EngineMySQL:
		return "CREATE USER 'scanx_ro'@'%' IDENTIFIED BY '<strong-password>';\n" +
			"GRANT SELECT, SHOW VIEW ON your_db.* TO 'scanx_ro'@'%';\n" +
			"-- nothing else: no INSERT/UPDATE/DELETE/ALTER/EXECUTE"
	case dbscan.EngineMSSQL:
		return "CREATE LOGIN scanx_ro WITH PASSWORD = '<strong-password>', CHECK_POLICY = ON;\n" +
			"USE YourDb;\n" +
			"CREATE USER scanx_ro FOR LOGIN scanx_ro;\n" +
			"GRANT VIEW DEFINITION TO scanx_ro;  -- structure only, no table data"
	}
	return "CREATE ROLE scanx_ro LOGIN PASSWORD '<strong-password>' NOSUPERUSER NOCREATEDB NOCREATEROLE;\n" +
		"GRANT CONNECT ON DATABASE your_db TO scanx_ro;\n" +
		"ALTER ROLE scanx_ro SET default_transaction_read_only = on;\n" +
		"-- PostgreSQL 14 and older allow CREATE in schema public for everyone:\n" +
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
}

func passwordPlaceholder(p *Page, d *service.DBConnDetail) string {
	if d == nil {
		return ""
	}
	if d.Conn.PasswordEnc == nil {
		return p.T("db.password_missing")
	}
	return p.T("db.password_keep")
}

func hourLabel(h int) string {
	if h < 10 {
		return "0" + strconv.Itoa(h) + ":00"
	}
	return strconv.Itoa(h) + ":00"
}

// errCode maps a check error code to a known hint key.
func errCode(code string) string {
	switch code {
	case "auth", "connect", "database", "tls", "blocked":
		return code
	}
	return "other"
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// Path0 is the current path without its query string.
func (p *Page) Path0() string {
	path, _, _ := strings.Cut(p.Path, "?")
	return path
}
