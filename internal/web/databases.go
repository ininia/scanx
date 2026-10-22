package web

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/dbscan"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/ui"
)

// moduleGate hides the pages of modules the organization may not use.
func (h *Handler) moduleGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := orgFrom(r)
		rest := strings.TrimPrefix(r.URL.Path, "/o/"+o.Org.Slug)
		module := ""
		switch {
		case strings.HasPrefix(rest, "/databases"):
			module = service.ModuleDB
		case strings.HasPrefix(rest, "/projects"), strings.HasPrefix(rest, "/scans"):
			module = service.ModuleRepo
		}
		if module != "" && !h.Svc.ModuleOf(r.Context(), o, module).Enabled {
			h.errorPage(w, r, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) mountDatabases(r chi.Router) {
	r.Get("/databases", h.databases)
	r.Get("/databases/new", h.dbNewForm)
	r.Post("/databases/new", h.dbNew)
	r.Get("/databases/rules", h.dbRules)
	r.Post("/databases/rules", h.dbRulesSave)
	r.Get("/databases/scans/{scan}", h.dbScanReport)
	r.Get("/databases/scans/{scan}/export/{format}", h.dbScanExport)
	r.Post("/databases/scans/{scan}/cancel", h.dbScanCancel)
	r.Get("/databases/{conn}", h.dbDetail)
	r.Get("/databases/{conn}/edit", h.dbEditForm)
	r.Post("/databases/{conn}/edit", h.dbEdit)
	r.Post("/databases/{conn}/verify", h.dbVerify)
	r.Post("/databases/{conn}/scan", h.dbScanNow)
	r.Post("/databases/{conn}/delete", h.dbDelete)
}

func (h *Handler) dbURL(r *http.Request, rest string) string {
	return "/o/" + orgFrom(r).Org.Slug + "/databases" + rest
}

func (h *Handler) databases(w http.ResponseWriter, r *http.Request) {
	list, err := h.Svc.ListDBConnections(r.Context(), orgFrom(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.Databases(h.page(r, "db.title", "databases"), list))
}

var dbFormKeys = []string{"name", "engine", "host", "port", "database", "user", "password", "tls", "schedule", "schedule_hour", "schedule_weekday", "exclude"}

func dbInput(f *ui.Form) service.DBConnInput {
	var ex []string
	for _, l := range strings.Split(f.V("exclude"), "\n") {
		for _, p := range strings.Split(l, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ex = append(ex, p)
			}
		}
	}
	return service.DBConnInput{
		Name: f.V("name"), Engine: f.V("engine"), Host: f.V("host"), Port: atoi(f.V("port"), 0), Database: f.V("database"),
		User: f.V("user"), Password: f.Values["password"], TLS: f.V("tls"), Schedule: f.V("schedule"),
		ScheduleHour: atoi(f.V("schedule_hour"), 3), ScheduleWeekday: atoi(f.V("schedule_weekday"), 1), Exclude: ex,
	}
}

func (h *Handler) dbForm(r *http.Request) *ui.Form {
	f := formFrom(r, dbFormKeys...)
	f.Values["password"] = r.PostFormValue("password") // never trimmed
	return f
}

func (h *Handler) renderDBForm(w http.ResponseWriter, r *http.Request, f *ui.Form, d *service.DBConnDetail, status int) {
	o := orgFrom(r)
	title := "db.new"
	if d != nil {
		title = "db.edit"
	}
	render(w, r, status, ui.DBConnForm(h.page(r, title, "databases"), f, d, h.Svc.ModuleOf(r.Context(), o, service.ModuleDB)))
}

func (h *Handler) dbNewForm(w http.ResponseWriter, r *http.Request) {
	if err := orgFrom(r).Require(auth.ActProjectWrite, "write"); err != nil {
		h.fail(w, r, err)
		return
	}
	f := ui.NewForm()
	f.Values["engine"], f.Values["tls"], f.Values["schedule"] = dbscan.EnginePostgres, "require", "daily"
	f.Values["schedule_hour"], f.Values["schedule_weekday"] = "3", "1"
	h.renderDBForm(w, r, f, nil, http.StatusOK)
}

func (h *Handler) dbNew(w http.ResponseWriter, r *http.Request) {
	f := h.dbForm(r)
	c, err := h.Svc.CreateDBConnection(r.Context(), orgFrom(r), dbInput(f), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		f.Values["password"] = ""
		h.renderDBForm(w, r, f, nil, http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, h.dbURL(r, "/"+c.ID.String()), "flash.db_created")
}

func (h *Handler) dbDetail(w http.ResponseWriter, r *http.Request) {
	d, err := h.Svc.GetDBConnection(r.Context(), orgFrom(r), chi.URLParam(r, "conn"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.DBConnDetail(h.page(r, "", "databases"), d))
}

func (h *Handler) dbEditForm(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		h.fail(w, r, err)
		return
	}
	d, err := h.Svc.GetDBConnection(r.Context(), o, chi.URLParam(r, "conn"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	c := d.Conn
	f := ui.NewForm()
	f.Values = map[string]string{
		"name": c.Name, "engine": c.Engine, "host": c.Host, "port": strconv.Itoa(int(c.Port)), "database": c.DatabaseName,
		"user": c.Username, "tls": c.TlsMode, "schedule": c.Schedule, "schedule_hour": strconv.Itoa(int(c.ScheduleHour)),
		"schedule_weekday": strconv.Itoa(int(c.ScheduleWeekday)), "exclude": strings.Join(c.Exclude, "\n"),
	}
	h.renderDBForm(w, r, f, d, http.StatusOK)
}

func (h *Handler) dbEdit(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	id := chi.URLParam(r, "conn")
	f := h.dbForm(r)
	c, err := h.Svc.UpdateDBConnection(r.Context(), o, id, dbInput(f), server.MetaFrom(r))
	if err != nil {
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		d, gerr := h.Svc.GetDBConnection(r.Context(), o, id)
		if gerr != nil {
			h.fail(w, r, gerr)
			return
		}
		f.Values["password"] = ""
		h.renderDBForm(w, r, f, d, http.StatusUnprocessableEntity)
		return
	}
	redirect(w, r, h.dbURL(r, "/"+c.ID.String()), "flash.saved")
}

func (h *Handler) dbVerify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "conn")
	if err := h.Svc.VerifyDBConnection(r.Context(), orgFrom(r), id); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.dbURL(r, "/"+id), "flash.db_verifying")
}

func (h *Handler) dbScanNow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "conn")
	sc, err := h.Svc.TriggerDBScan(r.Context(), orgFrom(r), id, server.MetaFrom(r))
	if errors.Is(err, service.ErrNotReady) {
		redirect(w, r, h.dbURL(r, "/"+id), "flash.db_not_ready")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.dbURL(r, "/scans/"+sc.ID.String()), "")
}

func (h *Handler) dbDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.DeleteDBConnection(r.Context(), orgFrom(r), chi.URLParam(r, "conn"), server.MetaFrom(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.dbURL(r, ""), "flash.deleted")
}

func (h *Handler) dbScanReport(w http.ResponseWriter, r *http.Request) {
	v, err := h.Svc.GetDBScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	filter := ui.DBFilter{Sev: q.Get("sev"), Cat: q.Get("cat"), Rule: q.Get("rule"), New: q.Get("new") == "1", Q: strings.TrimSpace(q.Get("q"))}
	render(w, r, http.StatusOK, ui.DBScanReport(h.page(r, "", "databases"), v, filter))
}

func (h *Handler) dbScanCancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "scan")
	if err := h.Svc.CancelDBScan(r.Context(), orgFrom(r), id); err != nil && !errors.Is(err, service.ErrConflict) {
		h.fail(w, r, err)
		return
	}
	redirect(w, r, h.dbURL(r, "/scans/"+id), "")
}

func (h *Handler) dbScanExport(w http.ResponseWriter, r *http.Request) {
	v, err := h.Svc.GetDBScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p := h.page(r, "", "databases")
	name := "scanx-db-" + v.Conn.Name + "-" + v.Scan.QueuedAt.Format("20060102-1504")
	name = strings.Map(func(c rune) rune {
		if c < 32 || c == '"' || c == '\\' || c == '/' {
			return '_'
		}
		return c
	}, name)
	switch chi.URLParam(r, "format") {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		out := map[string]any{
			"connection": map[string]any{"name": v.Conn.Name, "engine": v.Conn.Engine, "host": v.Conn.Host, "database": v.Conn.DatabaseName},
			"scan":       map[string]any{"id": v.Scan.ID, "status": v.Scan.Status, "score": v.Scan.Score, "grade": v.Scan.Grade, "gate": v.Scan.GateResult, "finished_at": v.Scan.FinishedAt},
			"summary":    v.Summary, "counts": v.Counts, "read_only": v.ReadOnly,
		}
		var fs []map[string]any
		for _, f := range v.Findings {
			fs = append(fs, map[string]any{
				"rule": f.RuleID, "title": p.T("dbrule." + f.RuleID + ".title"), "message": p.DBMessage(&f.Finding),
				"severity": f.Severity, "category": f.Category, "object_type": f.ObjectType, "object": f.Object,
				"details": f.Details, "new": f.IsNew, "fingerprint": f.Fingerprint,
			})
		}
		out["findings"] = fs
		_ = json.NewEncoder(w).Encode(out)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		_, _ = w.Write([]byte("\xef\xbb\xbf")) // BOM: Excel opens UTF-8 correctly
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"severity", "category", "rule", "title", "object_type", "object", "message", "new"})
		for _, f := range v.Findings {
			_ = cw.Write([]string{
				f.Severity, f.Category, f.RuleID, p.T("dbrule." + f.RuleID + ".title"), f.ObjectType,
				csvSafe(f.Object), csvSafe(p.DBMessage(&f.Finding)), strconv.FormatBool(f.IsNew),
			})
		}
		cw.Flush()
	default:
		h.errorPage(w, r, http.StatusNotFound)
	}
}

// csvSafe defuses spreadsheet formulas in database-provided names.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ---------- rule profile ----------

func (h *Handler) dbRules(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	prof, err := h.Svc.DBProfile(r.Context(), o)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	render(w, r, http.StatusOK, ui.DBRules(h.page(r, "db.rules", "databases"), ui.NewForm(), prof))
}

func (h *Handler) dbRulesSave(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, err)
		return
	}
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	prof := dbscan.Profile{
		Language: v("language"), TableCase: v("table_case"), ColumnCase: v("column_case"), TableNumber: v("table_number"),
		MaxNameLength: atoi(v("max_name_length"), 0), MaxColumns: atoi(v("max_columns"), 0), FailOn: v("fail_on"),
		AuditNames: map[string]string{}, Rules: map[string]dbscan.RuleSetting{},
	}
	req := r.PostFormValue("require_audit") == "on"
	prof.RequireAudit = &req
	for _, c := range dbscan.AuditConcepts {
		if n := v("audit_" + c); n != "" {
			prof.AuditNames[c] = n
		}
	}
	for _, l := range strings.Split(r.PostFormValue("exclude"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			prof.Exclude = append(prof.Exclude, l)
		}
	}
	for _, rule := range dbscan.Rules {
		on := r.PostFormValue("rule_"+rule.ID) == "on"
		sev := v("sev_" + rule.ID)
		rs := dbscan.RuleSetting{}
		if on != rule.DefaultOn {
			rs.Enabled = &on
		}
		if sev != "" && sev != rule.Severity {
			rs.Severity = sev
		}
		if rs.Enabled != nil || rs.Severity != "" {
			prof.Rules[rule.ID] = rs
		}
	}
	if err := h.Svc.SaveDBProfile(r.Context(), o, prof, server.MetaFrom(r)); err != nil {
		f := ui.NewForm()
		if !formErr(f, err) {
			h.fail(w, r, err)
			return
		}
		render(w, r, http.StatusUnprocessableEntity, ui.DBRules(h.page(r, "db.rules", "databases"), f, prof))
		return
	}
	redirect(w, r, h.dbURL(r, "/rules"), "flash.saved")
}

// ---------- instance admin: modules ----------

func (h *Handler) adminOrg(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Svc.AdminOrgModules(r.Context(), auth.PrincipalFrom(r.Context()))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	for _, row := range rows {
		if row.Org.ID == id {
			render(w, r, http.StatusOK, ui.AdminOrg(h.page(r, "admin.org", "admin"), row))
			return
		}
	}
	h.errorPage(w, r, http.StatusNotFound)
}

func (h *Handler) adminOrgModules(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, err)
		return
	}
	for _, m := range service.AllModules {
		st := service.ModuleSettings{
			MaxItems: atoi(r.PostFormValue(m+"_max"), 0), NoSchedule: r.PostFormValue(m+"_no_schedule") == "on",
			NoNotifications: r.PostFormValue(m+"_no_notifications") == "on", AdminsOnly: r.PostFormValue(m+"_admins_only") == "on",
		}
		if err := h.Svc.SetOrgModule(r.Context(), p, id, m, r.PostFormValue(m+"_enabled") == "on", st, server.MetaFrom(r)); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	redirect(w, r, "/admin/orgs/"+id.String(), "flash.saved")
}
