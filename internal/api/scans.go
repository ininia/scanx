package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store/db"
)

const maxWebhookBody = 5 << 20

// webhook receives push events from Git providers (no session, no token:
// authenticated by the per-project HMAC secret).
func (h *Handler) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		server.WriteError(w, r, http.StatusRequestEntityTooLarge, "too_large", "Payload too large")
		return
	}
	res, err := h.Svc.HandleWebhook(r.Context(), chi.URLParam(r, "provider"), chi.URLParam(r, "project"), r.Header, body)
	switch {
	case errors.Is(err, service.ErrWebhookSignature):
		server.WriteError(w, r, http.StatusUnauthorized, "invalid_signature", "Invalid webhook signature")
		return
	case errors.Is(err, service.ErrWebhookPayload):
		server.WriteError(w, r, http.StatusBadRequest, "bad_request", "Unsupported webhook payload")
		return
	case err != nil:
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, res.Status, res)
}

type scanOutJSON struct {
	ID            uuid.UUID       `json:"id"`
	ProjectID     uuid.UUID       `json:"project_id"`
	Trigger       string          `json:"trigger"`
	Branch        string          `json:"branch"`
	CommitSHA     string          `json:"commit_sha"`
	CommitMessage string          `json:"commit_message"`
	Status        string          `json:"status"`
	StatusReason  string          `json:"status_reason"`
	Partial       bool            `json:"partial"`
	GateResult    *string         `json:"gate_result"`
	Score         *int32          `json:"score"`
	NewIssues     int32           `json:"new_issues"`
	FixedIssues   int32           `json:"fixed_issues"`
	Summary       json.RawMessage `json:"summary"`
	QueuedAt      time.Time       `json:"queued_at"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
}

func scanOut(s *db.Scan) scanOutJSON {
	sum := s.Summary
	if len(sum) == 0 {
		sum = json.RawMessage(`{}`)
	}
	return scanOutJSON{
		ID: s.ID, ProjectID: s.ProjectID, Trigger: s.Trigger, Branch: s.Branch, CommitSHA: s.CommitSha,
		CommitMessage: s.CommitMessage, Status: s.Status, StatusReason: s.StatusReason, Partial: s.Partial,
		GateResult: s.GateResult, Score: s.Score, NewIssues: s.NewIssues, FixedIssues: s.FixedIssues, Summary: sum,
		QueuedAt: s.QueuedAt, StartedAt: s.StartedAt, FinishedAt: s.FinishedAt,
	}
}

type issueOutJSON struct {
	ID          uuid.UUID `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	RuleID      string    `json:"rule_id"`
	File        string    `json:"file"`
	StartLine   int32     `json:"start_line"`
	CWE         []string  `json:"cwe"`
	CVE         []string  `json:"cve"`
	Sources     []string  `json:"sources"`
	Status      string    `json:"status"`
	IsNew       *bool     `json:"is_new,omitempty"`
}

func issueOut(i *db.Issue) issueOutJSON {
	return issueOutJSON{
		ID: i.ID, Fingerprint: i.Fingerprint, Category: i.Category, Severity: i.Severity, Title: i.Title,
		RuleID: i.RuleID, File: i.File, StartLine: i.StartLine, CWE: nonNil(i.Cwe), CVE: nonNil(i.Cve),
		Sources: nonNil(i.Sources), Status: i.Status,
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *Handler) deployKey(w http.ResponseWriter, r *http.Request) {
	k, err := h.Svc.ProjectDeployKey(r.Context(), orgFrom(r), chi.URLParam(r, "project"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	if k == nil {
		writeErr(w, r, service.ErrNotFound)
		return
	}
	server.WriteJSON(w, r, http.StatusOK, map[string]string{"public_key": k.PublicKey, "fingerprint": k.Fingerprint})
}

func (h *Handler) createScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Branch string `json:"branch"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	sc, err := h.Svc.TriggerScan(r.Context(), orgFrom(r), chi.URLParam(r, "project"), req.Branch, service.TriggerAPI, server.MetaFrom(r))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusAccepted, scanOut(sc))
}

func (h *Handler) listScans(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	p, err := h.Svc.GetProject(r.Context(), o, chi.URLParam(r, "project"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	scans, err := h.Svc.ListProjectScans(r.Context(), o, p, 50)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]scanOutJSON, 0, len(scans))
	for i := range scans {
		out = append(out, scanOut(&scans[i]))
	}
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	v, err := h.Svc.GetScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), true)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	tools := make([]map[string]any, 0, len(v.Tools))
	for _, t := range v.Tools {
		tools = append(tools, map[string]any{
			"id": t.ToolID, "name": t.Name, "version": t.ToolVersion, "status": t.Status,
			"duration_ms": t.DurationMs, "findings": t.FindingsCount, "error": t.Error,
		})
	}
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"scan": scanOut(&v.Scan), "project": v.Project.Slug, "tools": tools})
}

func (h *Handler) scanIssues(w http.ResponseWriter, r *http.Request) {
	v, err := h.Svc.GetScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), true)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]issueOutJSON, 0, len(v.Issues))
	for _, row := range v.Issues {
		i := db.Issue{
			ID: row.ID, Fingerprint: row.Fingerprint, Category: row.Category, Severity: row.Severity,
			Title: row.Title, RuleID: row.RuleID, File: row.File, StartLine: row.StartLine, Cwe: row.Cwe, Cve: row.Cve,
			Sources: row.Sources, Status: row.Status,
		}
		o := issueOut(&i)
		isNew := row.IsNew
		o.IsNew = &isNew
		out = append(out, o)
	}
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) cancelScan(w http.ResponseWriter, r *http.Request) {
	if err := h.Svc.CancelScan(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReportContentTypes for downloads.
var reportTypes = map[string][2]string{
	"json":  {"application/json", "scanx.json"},
	"sarif": {"application/sarif+json", "scanx.sarif"},
	"html":  {"text/html; charset=utf-8", "scanx.html"},
	"sbom":  {"application/vnd.cyclonedx+json", "sbom.cdx.json"},
}

func (h *Handler) scanReport(w http.ResponseWriter, r *http.Request) {
	format := chi.URLParam(r, "format")
	gz, err := h.Svc.ScanReport(r.Context(), orgFrom(r), chi.URLParam(r, "scan"), format)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	WriteReport(w, r, gz, format, true)
}

// WriteReport serves a stored gzip report. HTML reports are rendered in a
// locked-down sandbox (no scripts, no same-origin access).
func WriteReport(w http.ResponseWriter, r *http.Request, gz []byte, format string, download bool) {
	t := reportTypes[format]
	w.Header().Set("Content-Type", t[0])
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if download {
		w.Header().Set("Content-Disposition", `attachment; filename="`+t[1]+`"`)
	}
	w.Header().Set("Vary", "Accept-Encoding")
	if acceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz) //nolint:gosec // stored scan report, served with a sandbox CSP and nosniff
		return
	}
	zr, err := newGzipReader(gz)
	if err != nil {
		http.Error(w, "corrupt report", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, zr)
}

func (h *Handler) projectIssues(w http.ResponseWriter, r *http.Request) {
	o := orgFrom(r)
	p, err := h.Svc.GetProject(r.Context(), o, chi.URLParam(r, "project"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	issues, err := h.Svc.ProjectIssues(r.Context(), o, p, r.URL.Query().Get("status"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	out := make([]issueOutJSON, 0, len(issues))
	for i := range issues {
		out = append(out, issueOut(&issues[i]))
	}
	server.WriteJSON(w, r, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) updateIssue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	o := orgFrom(r)
	if err := h.Svc.SetIssueStatus(r.Context(), o, chi.URLParam(r, "issue"), req.Status, req.Reason, server.MetaFrom(r)); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err := h.Svc.GetIssue(r.Context(), o, chi.URLParam(r, "issue"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	server.WriteJSON(w, r, http.StatusOK, issueOut(&v.Issue))
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, q, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") && strings.TrimSpace(q) != "q=0" {
			return true
		}
	}
	return false
}

func newGzipReader(b []byte) (io.Reader, error) { return gzip.NewReader(bytes.NewReader(b)) }
