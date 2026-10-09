package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/gitfetch"
	"github.com/ininia/scanx/internal/sshkeys"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Job kinds.
const (
	JobScan           = "scan"
	JobTestConnection = "test_connection"
)

// Scan triggers.
const (
	TriggerManual  = "manual"
	TriggerWebhook = "webhook"
	TriggerAPI     = "api"
)

// DeployKeyAAD binds an encrypted deploy key to its project.
func DeployKeyAAD(projectID uuid.UUID) []byte { return []byte("deploykey:" + projectID.String()) }

// WebhookSecretAAD binds an encrypted webhook secret to its project.
func WebhookSecretAAD(projectID uuid.UUID) []byte { return []byte("webhook:" + projectID.String()) }

// DeployKey is the public half of a project's deploy key.
type DeployKey struct {
	PublicKey   string
	Fingerprint string
}

func (s *Service) createDeployKey(ctx context.Context, q *db.Queries, p *db.Project) (*DeployKey, error) {
	k, err := sshkeys.Generate("scanx-" + p.Slug)
	if err != nil {
		return nil, err
	}
	ct, nonce, err := s.box.Seal(k.PrivatePEM, DeployKeyAAD(p.ID))
	if err != nil {
		return nil, err
	}
	if err := q.CreateSSHKey(ctx, db.CreateSSHKeyParams{
		ID: newID(), OrgID: p.OrgID, ProjectID: p.ID, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint,
		PrivateKeyEnc: ct, Nonce: nonce,
	}); err != nil {
		return nil, err
	}
	return &DeployKey{PublicKey: k.PublicKey, Fingerprint: k.Fingerprint}, nil
}

func (s *Service) createWebhookSecret(ctx context.Context, q *db.Queries, p *db.Project) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(b)
	ct, nonce, err := s.box.Seal([]byte(secret), WebhookSecretAAD(p.ID))
	if err != nil {
		return "", err
	}
	return secret, q.SetWebhookSecret(ctx, db.SetWebhookSecretParams{OrgID: p.OrgID, ID: p.ID, WebhookSecretEnc: ct, WebhookSecretNonce: nonce})
}

// ProjectDeployKey returns the project's deploy key, creating one for
// projects made before deploy keys existed.
func (s *Service) ProjectDeployKey(ctx context.Context, o *OrgCtx, slug string) (*DeployKey, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return nil, err
	}
	var dk *DeployKey
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		k, err := q.GetActiveSSHKey(ctx, db.GetActiveSSHKeyParams{OrgID: o.Org.ID, ProjectID: p.ID})
		if err == nil {
			dk = &DeployKey{PublicKey: k.PublicKey, Fingerprint: k.Fingerprint}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if o.Require(auth.ActProjectWrite, "write") != nil {
			return nil
		}
		dk, err = s.createDeployKey(ctx, q, p)
		return err
	})
	return dk, wrap("deploy key", err)
}

// RotateDeployKey replaces the deploy key. The old key stays decryptable for
// a grace period but is no longer used.
func (s *Service) RotateDeployKey(ctx context.Context, o *OrgCtx, slug string, m Meta) (*DeployKey, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return nil, err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return nil, err
	}
	var dk *DeployKey
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.RetireSSHKeys(ctx, db.RetireSSHKeysParams{OrgID: o.Org.ID, ProjectID: p.ID}); err != nil {
			return err
		}
		var err error
		if dk, err = s.createDeployKey(ctx, q, p); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.deploy_key_rotated", "project", p.ID.String(), m,
			map[string]any{"fingerprint": dk.Fingerprint})
	})
	return dk, wrap("rotate deploy key", err)
}

// WebhookSecret reveals the project's webhook secret (creating it if
// missing). Only members who may change the project can see it.
func (s *Service) WebhookSecret(ctx context.Context, o *OrgCtx, slug string) (string, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return "", err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return "", err
	}
	if len(p.WebhookSecretEnc) > 0 {
		pt, err := s.box.Open(p.WebhookSecretEnc, p.WebhookSecretNonce, WebhookSecretAAD(p.ID))
		if err != nil {
			return "", wrap("webhook secret", err)
		}
		return string(pt), nil
	}
	var secret string
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		secret, err = s.createWebhookSecret(ctx, q, p)
		return err
	})
	return secret, wrap("webhook secret", err)
}

// RotateWebhookSecret issues a new webhook secret; the provider's webhook
// must be updated afterwards.
func (s *Service) RotateWebhookSecret(ctx context.Context, o *OrgCtx, slug string, m Meta) (string, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return "", err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return "", err
	}
	var secret string
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if secret, err = s.createWebhookSecret(ctx, q, p); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.webhook_secret_rotated", "project", p.ID.String(), m, nil)
	})
	return secret, wrap("rotate webhook secret", err)
}

// FailOnLevels are the accepted quality gate thresholds.
var FailOnLevels = []string{"critical", "high", "medium", "low", "info", "none"}

// UpdateScanSettings changes the quality gate and history scanning.
func (s *Service) UpdateScanSettings(ctx context.Context, o *OrgCtx, slug, failOn string, history bool, m Meta) error {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return err
	}
	ok := false
	for _, l := range FailOnLevels {
		ok = ok || l == failOn
	}
	if !ok {
		return invalid("fail_on", "invalid")
	}
	return wrap("scan settings", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.UpdateProjectScanSettings(ctx, db.UpdateProjectScanSettingsParams{OrgID: o.Org.ID, ID: p.ID, FailOn: failOn, ScanHistory: history}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "project.scan_settings_updated", "project", p.ID.String(), m,
			map[string]any{"fail_on": failOn, "history": history})
	}))
}

// enqueueScan creates a scan and its job. It returns (nil, nil) when an
// identical scan (same branch and commit) is already queued or running.
func enqueueScan(ctx context.Context, q *db.Queries, p *db.Project, trigger string, by *uuid.UUID, branch, commit, msg, author string) (*db.Scan, error) {
	sc, err := q.CreateScan(ctx, db.CreateScanParams{
		ID: newID(), OrgID: p.OrgID, ProjectID: p.ID, Trigger: trigger, TriggeredBy: by, Branch: branch,
		CommitSha: commit, CommitMessage: trunc(msg, 500), CommitAuthor: trunc(author, 200),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := q.EnqueueJob(ctx, db.EnqueueJobParams{ID: newID(), OrgID: p.OrgID, Kind: JobScan, ProjectID: p.ID, ScanID: &sc.ID}); err != nil {
		return nil, err
	}
	return &sc, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// DefaultBranch is the branch scanned when the user does not pick one: the
// first configured branch that is not a pattern.
func DefaultBranch(p *db.Project) string {
	for _, b := range p.Branches {
		if !strings.ContainsAny(b, "*?[") {
			return b
		}
	}
	return "main"
}

// TriggerScan queues a manual scan of branch (default: the project's first
// branch). Repeated clicks while a scan is still queued return that scan.
func (s *Service) TriggerScan(ctx context.Context, o *OrgCtx, slug, branch, trigger string, m Meta) (*db.Scan, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return nil, err
	}
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return nil, err
	}
	if p.ArchivedAt != nil {
		return nil, invalid("project", "archived")
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = DefaultBranch(p)
	}
	if !gitfetch.ValidBranch(branch) {
		return nil, invalid("branch", "invalid")
	}
	if trigger == "" {
		trigger = TriggerManual
	}
	var sc *db.Scan
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if cur, err := q.ActiveManualScan(ctx, db.ActiveManualScanParams{OrgID: o.Org.ID, ProjectID: p.ID, Branch: branch}); err == nil {
			sc = &cur
			return nil
		}
		var err error
		if sc, err = enqueueScan(ctx, q, p, trigger, &o.P.UserID, branch, "", "", ""); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "scan.triggered", "scan", sc.ID.String(), m,
			map[string]any{"project": p.Slug, "branch": branch, "trigger": trigger})
	})
	if err != nil {
		return nil, wrap("trigger scan", err)
	}
	return sc, nil
}

// ListProjectScans returns a project's most recent scans.
func (s *Service) ListProjectScans(ctx context.Context, o *OrgCtx, p *db.Project, limit int) ([]db.Scan, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	var out []db.Scan
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListProjectScans(ctx, db.ListProjectScansParams{OrgID: o.Org.ID, ProjectID: p.ID, Limit: int32(limit)}) //nolint:gosec // bounded
		return err
	})
	return out, wrap("list scans", err)
}

// ListRecentScans returns the org's most recent scans across projects.
func (s *Service) ListRecentScans(ctx context.Context, o *OrgCtx, limit int) ([]db.ListOrgScansRow, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	var out []db.ListOrgScansRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListOrgScans(ctx, db.ListOrgScansParams{OrgID: o.Org.ID, Limit: int32(limit)}) //nolint:gosec // bounded
		return err
	})
	return out, wrap("list scans", err)
}

// ScanView is a scan with its project, tool runs and issues.
type ScanView struct {
	Scan    db.Scan
	Project db.Project
	Tools   []db.ScanTool
	Issues  []db.ListScanIssuesRow
}

// Active reports whether the scan has not finished yet.
func (v *ScanView) Active() bool { return ScanActive(v.Scan.Status) }

// ScanActive reports whether a scan status is non-terminal.
func ScanActive(status string) bool {
	switch status {
	case "queued", "cloning", "scanning", "reporting":
		return true
	}
	return false
}

func parseID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, ErrNotFound
	}
	return id, nil
}

// GetScan loads a scan. withDetails also loads tools and issues.
func (s *Service) GetScan(ctx context.Context, o *OrgCtx, scanID string, withDetails bool) (*ScanView, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	id, err := parseID(scanID)
	if err != nil {
		return nil, err
	}
	v := &ScanView{}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if v.Scan, err = q.GetScan(ctx, db.GetScanParams{OrgID: o.Org.ID, ID: id}); err != nil {
			return store.NotFound(err)
		}
		if v.Project, err = q.GetProjectByID(ctx, v.Scan.ProjectID); err != nil {
			return store.NotFound(err)
		}
		if !withDetails {
			return nil
		}
		if v.Tools, err = q.ListScanTools(ctx, db.ListScanToolsParams{OrgID: o.Org.ID, ScanID: id}); err != nil {
			return err
		}
		v.Issues, err = q.ListScanIssues(ctx, db.ListScanIssuesParams{OrgID: o.Org.ID, ScanID: id})
		return err
	})
	if err != nil {
		return nil, wrap("get scan", err)
	}
	return v, nil
}

// CancelScan stops a queued or running scan.
func (s *Service) CancelScan(ctx context.Context, o *OrgCtx, scanID string, m Meta) error {
	if err := o.Require(auth.ActScanTrigger, "write"); err != nil {
		return err
	}
	id, err := parseID(scanID)
	if err != nil {
		return err
	}
	return wrap("cancel scan", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		// Invisible (other tenant) or unknown → 404; finished → 409.
		if _, err := q.GetScan(ctx, db.GetScanParams{OrgID: o.Org.ID, ID: id}); err != nil {
			return store.NotFound(err)
		}
		n, err := q.CancelScan(ctx, db.CancelScanParams{OrgID: o.Org.ID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrConflict
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "scan.canceled", "scan", id.String(), m, nil)
	}))
}

// ReportFormats that can be downloaded.
var ReportFormats = map[string]bool{"html": true, "json": true, "sarif": true, "sbom": true}

// ScanReport returns a stored report (gzip-compressed).
func (s *Service) ScanReport(ctx context.Context, o *OrgCtx, scanID, format string) ([]byte, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	id, err := parseID(scanID)
	if err != nil {
		return nil, err
	}
	if !ReportFormats[format] {
		return nil, ErrNotFound
	}
	var gz []byte
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		gz, err = q.GetReport(ctx, db.GetReportParams{OrgID: o.Org.ID, ScanID: id, Format: format})
		return store.NotFound(err)
	})
	return gz, wrap("report", err)
}

// IssueStatuses users may set.
var IssueStatuses = map[string]bool{"open": true, "false_positive": true, "accepted_risk": true, "wont_fix": true}

// ProjectIssues lists a project's issues (status "" = all).
func (s *Service) ProjectIssues(ctx context.Context, o *OrgCtx, p *db.Project, status string) ([]db.Issue, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	if status != "" && !IssueStatuses[status] && status != "fixed" {
		return nil, invalid("status", "invalid")
	}
	var out []db.Issue
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListProjectIssues(ctx, db.ListProjectIssuesParams{OrgID: o.Org.ID, ProjectID: p.ID, Status: status})
		return err
	})
	return out, wrap("list issues", err)
}

// IssueView is an issue with its history.
type IssueView struct {
	Issue   db.Issue
	Project db.Project
	Events  []db.ListIssueEventsRow
}

// GetIssue loads an issue and its events.
func (s *Service) GetIssue(ctx context.Context, o *OrgCtx, issueID string) (*IssueView, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	id, err := parseID(issueID)
	if err != nil {
		return nil, err
	}
	v := &IssueView{}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if v.Issue, err = q.GetIssue(ctx, db.GetIssueParams{OrgID: o.Org.ID, ID: id}); err != nil {
			return store.NotFound(err)
		}
		if v.Project, err = q.GetProjectByID(ctx, v.Issue.ProjectID); err != nil {
			return store.NotFound(err)
		}
		v.Events, err = q.ListIssueEvents(ctx, db.ListIssueEventsParams{OrgID: o.Org.ID, IssueID: id})
		return err
	})
	if err != nil {
		return nil, wrap("get issue", err)
	}
	return v, nil
}

// SetIssueStatus records a triage decision (false positive, accepted risk…).
func (s *Service) SetIssueStatus(ctx context.Context, o *OrgCtx, issueID, status, reason string, m Meta) error {
	if err := o.Require(auth.ActIssueUpdate, "write"); err != nil {
		return err
	}
	if !IssueStatuses[status] {
		return invalid("status", "invalid")
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) > 1000 {
		return invalid("reason", "length")
	}
	if status != "open" && reason == "" {
		return invalid("reason", "required")
	}
	v, err := s.GetIssue(ctx, o, issueID)
	if err != nil {
		return err
	}
	return wrap("update issue", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.UpdateIssueStatus(ctx, db.UpdateIssueStatusParams{OrgID: o.Org.ID, ID: v.Issue.ID, Status: status, StatusReason: reason}); err != nil {
			return err
		}
		if err := q.InsertIssueEvent(ctx, db.InsertIssueEventParams{
			ID: newID(), OrgID: o.Org.ID, IssueID: v.Issue.ID, UserID: &o.P.UserID, Kind: "status",
			FromValue: v.Issue.Status, ToValue: status, Comment: reason,
		}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "issue.status_changed", "issue", v.Issue.ID.String(), m,
			map[string]any{"from": v.Issue.Status, "to": status})
	}))
}

// TestConnection queues a connection test (git ls-remote with the deploy
// key) and returns the job id to poll.
func (s *Service) TestConnection(ctx context.Context, o *OrgCtx, slug string) (uuid.UUID, error) {
	p, err := s.GetProject(ctx, o, slug)
	if err != nil {
		return uuid.Nil, err
	}
	if err := o.Require(auth.ActProjectWrite, "write"); err != nil {
		return uuid.Nil, err
	}
	id := newID()
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		return q.EnqueueJob(ctx, db.EnqueueJobParams{ID: id, OrgID: o.Org.ID, Kind: JobTestConnection, ProjectID: p.ID})
	})
	return id, wrap("test connection", err)
}

// GetJob returns a job of the org.
func (s *Service) GetJob(ctx context.Context, o *OrgCtx, jobID string) (*db.Job, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	id, err := parseID(jobID)
	if err != nil {
		return nil, err
	}
	var j db.Job
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		j, err = q.GetJob(ctx, db.GetJobParams{OrgID: o.Org.ID, ID: id})
		return store.NotFound(err)
	})
	if err != nil {
		return nil, wrap("get job", err)
	}
	return &j, nil
}

// OrgStats feeds the dashboard.
type OrgStats struct {
	Open        map[string]int                         // severity → open issues
	ByProject   map[uuid.UUID]map[string]int           // project → severity → open
	LastScan    map[uuid.UUID]db.LastScanPerProjectRow // project → latest scan
	RecentScans []db.ListOrgScansRow
}

// Stats returns dashboard numbers.
func (s *Service) Stats(ctx context.Context, o *OrgCtx) (*OrgStats, error) {
	if err := o.Require(auth.ActProjectRead, "read"); err != nil {
		return nil, err
	}
	st := &OrgStats{Open: map[string]int{}, ByProject: map[uuid.UUID]map[string]int{}, LastScan: map[uuid.UUID]db.LastScanPerProjectRow{}}
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		open, err := q.CountOpenIssues(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		for _, r := range open {
			st.Open[r.Severity] = int(r.N)
		}
		byp, err := q.CountOpenIssuesByProject(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		for _, r := range byp {
			if st.ByProject[r.ProjectID] == nil {
				st.ByProject[r.ProjectID] = map[string]int{}
			}
			st.ByProject[r.ProjectID][r.Severity] = int(r.N)
		}
		last, err := q.LastScanPerProject(ctx, o.Org.ID)
		if err != nil {
			return err
		}
		for _, r := range last {
			st.LastScan[r.ProjectID] = r
		}
		st.RecentScans, err = q.ListOrgScans(ctx, db.ListOrgScansParams{OrgID: o.Org.ID, Limit: 8})
		return err
	})
	return st, wrap("stats", err)
}

// EnsureProjectCredentials creates missing deploy keys and webhook secrets
// (projects created before Faz 3). Run once at server startup.
func (s *Service) EnsureProjectCredentials(ctx context.Context) (int, error) {
	n := 0
	err := s.db.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		ps, err := q.ProjectsMissingCredentials(ctx)
		if err != nil {
			return err
		}
		for i := range ps {
			p := &ps[i]
			if _, err := q.GetActiveSSHKey(ctx, db.GetActiveSSHKeyParams{OrgID: p.OrgID, ProjectID: p.ID}); errors.Is(err, pgx.ErrNoRows) {
				if _, err := s.createDeployKey(ctx, q, p); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if len(p.WebhookSecretEnc) == 0 {
				if _, err := s.createWebhookSecret(ctx, q, p); err != nil {
					return err
				}
			}
			n++
		}
		return nil
	})
	return n, wrap("ensure project credentials", err)
}
