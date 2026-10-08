package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/gitfetch"
	"github.com/ininia/scanx/internal/gitutil"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/report"
	"github.com/ininia/scanx/internal/sandbox"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

var errCanceled = errors.New("scan canceled by a user")

// scanFailure ends a scan with a reason shown to users. code selects a
// translated explanation in the UI (fail.<code>); reason holds the details.
type scanFailure struct{ code, reason string }

func (e *scanFailure) Error() string { return e.reason }

// reportFiles maps files in /work/out to stored report formats.
var reportFiles = map[string]string{
	"scanx.json": "json", "scanx.sarif": "sarif", "scanx.html": "html", "sbom.cdx.json": "sbom",
}

const maxReportBytes = 256 << 20

func (w *Worker) setStatus(ctx context.Context, scanID uuid.UUID, status, reason string) {
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		return q.SetScanStatus(ctx, db.SetScanStatusParams{ID: scanID, Status: status, StatusReason: reason})
	})
}

func (w *Worker) runScan(ctx context.Context, job *db.Job, log *slog.Logger) error {
	if job.ScanID == nil {
		return errors.New("scan job without scan")
	}
	var sc db.Scan
	if err := w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		var err error
		sc, err = q.GetScanByID(ctx, *job.ScanID)
		return store.NotFound(err)
	}); err != nil {
		return err
	}
	if !service.ScanActive(sc.Status) {
		return nil // canceled (or finished by an earlier attempt)
	}
	p, err := w.project(ctx, sc.ProjectID)
	if err != nil {
		return err
	}
	log = log.With("scan", sc.ID, "project", p.Slug, "branch", sc.Branch)
	log.Info("scan started")

	sctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	tctx, tcancel := context.WithTimeoutCause(sctx, w.cfg.FetchTimeout+w.cfg.ScanTimeout,
		&scanFailure{code: "scan_timeout", reason: "The scan exceeded the time limit (SCANX_SCAN_TIMEOUT)."})
	defer tcancel()
	go w.watchCancel(tctx, sc.ID, cancel)

	rep, files, meta, err := w.execute(tctx, job, &sc, p)
	if ctx.Err() != nil {
		return ctx.Err() // shutdown: retried later
	}
	if err != nil {
		code, reason := "internal", err.Error()
		var sf *scanFailure
		var fe *fetchError
		switch {
		case errors.Is(err, errCanceled):
			log.Info("scan canceled")
			return nil
		case errors.As(err, &sf):
			code = sf.code
		case errors.As(err, &fe):
			code = fe.code
		}
		w.failScan(ctx, &sc, p, code, reason)
		log.Warn("scan failed", "reason", reason)
		return nil
	}
	if err := w.persist(ctx, &sc, p, rep, files, meta); err != nil {
		w.failScan(ctx, &sc, p, "internal", "Saving results failed: "+err.Error())
		return err
	}
	log.Info("scan completed", "gate", rep.Gate.Result, "issues", len(rep.Issues), "score", rep.Score)
	return nil
}

func (w *Worker) watchCancel(ctx context.Context, id uuid.UUID, cancel context.CancelCauseFunc) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var canceled bool
		_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
			var err error
			canceled, err = q.IsScanCanceled(ctx, id)
			return err
		})
		if canceled {
			cancel(errCanceled)
			return
		}
	}
}

type fetchMeta struct {
	commit, message, author string
	sizeMB                  int
}

// execute runs fetch + scan and returns the parsed report and raw files.
func (w *Worker) execute(ctx context.Context, job *db.Job, sc *db.Scan, p *db.Project) (*report.Report, map[string][]byte, *fetchMeta, error) {
	w.setStatus(ctx, sc.ID, "cloning", "")
	env, err := w.fetchEnv(ctx, p, gitfetch.ModeClone)
	if err != nil {
		return nil, nil, nil, err
	}
	env = append(env, "SCANX_BRANCH="+sc.Branch)
	if sc.CommitSha != "" {
		env = append(env, "SCANX_COMMIT="+sc.CommitSha)
	}

	volume := fmt.Sprintf("scanx-%s-%d", sc.ID, job.Attempts)
	if err := w.docker.CreateVolume(ctx, volume, labels(job, "volume")); err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := w.docker.RemoveVolume(rctx, volume); err != nil {
			w.log.Error("remove scan volume (source code!)", "volume", volume, "err", err)
		}
	}()

	fctx, fcancel := context.WithTimeoutCause(ctx, w.cfg.FetchTimeout, &scanFailure{code: "timeout", reason: "Cloning took too long and was stopped."})
	_, stdout, stderr, err := w.runContainer(fctx, w.fetchSpec(job, env, volume), nil)
	fcancel()
	if err != nil {
		return nil, nil, nil, err
	}
	fr, err := gitfetch.ParseResult(stdout)
	if err != nil {
		return nil, nil, nil, &scanFailure{code: "git", reason: "Cloning failed: " + tail(stderr, 800)}
	}
	if !fr.OK {
		return nil, nil, nil, &scanFailure{code: fr.Code, reason: fr.Error}
	}
	meta := &fetchMeta{commit: fr.Commit, message: fr.Message, author: fr.Author, sizeMB: fr.SizeMB}
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		msg, author := sc.CommitMessage, sc.CommitAuthor
		if msg == "" {
			msg = fr.Message
		}
		if author == "" {
			author = fr.Author
		}
		return q.SetScanCommit(ctx, db.SetScanCommitParams{ID: sc.ID, CommitSha: fr.Commit, CommitMessage: msg, CommitAuthor: author})
	})
	sc.CommitSha = fr.Commit

	w.setStatus(ctx, sc.ID, "scanning", "")
	repoName := p.Name
	if r, err := gitutil.ParseRepoURL(p.RepoUrl); err == nil {
		repoName = r.Host + "/" + r.Path
	}
	cmd := []string{
		"scan", "--engine", "exec", "--path", "/work/src", "--out", "/work/out",
		"--format", "json,sarif,html", "--fail-on", p.FailOn, "--profile", w.cfg.Profile,
		"--history=" + strconv.FormatBool(p.ScanHistory), "--parallelism", strconv.Itoa(max(w.cfg.Parallelism, 1)),
		"--branch", sc.Branch, "--commit", fr.Commit, "--repo", repoName, "--display-path", repoName,
	}
	files := map[string][]byte{}
	spec := sandbox.ContainerSpec{
		Image: w.cfg.Image, Cmd: cmd, User: "65532:65532", Labels: labels(job, "scan"),
		Mounts:      []sandbox.Mount{{Type: "volume", Source: volume, Target: "/work"}},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=2g"},
		Network:     "none",
		MemoryBytes: w.cfg.MemoryBytes, NanoCPUs: w.cfg.NanoCPUs, PidsLimit: 1024, Runtime: w.cfg.Runtime,
	}
	sctx, scancel := context.WithTimeoutCause(ctx, w.cfg.ScanTimeout,
		&scanFailure{code: "scan_timeout", reason: "The scan exceeded the time limit (SCANX_SCAN_TIMEOUT)."})
	defer scancel()
	code, _, stderr, err := w.runContainer(sctx, spec, func(id string) error {
		return w.collect(sctx, id, files)
	})
	switch {
	case errors.Is(err, errOOM):
		return nil, nil, nil, &scanFailure{code: "oom", reason: "The scanners ran out of memory (SCANX_SCANNER_MEMORY)."}
	case err != nil:
		return nil, nil, nil, err
	}
	raw, ok := files["json"]
	if !ok || code > 2 || code < 0 {
		return nil, nil, nil, &scanFailure{code: "no_report", reason: fmt.Sprintf("The scanner exited with code %d without a report: %s", code, tail(stderr, 800))}
	}
	w.setStatus(ctx, sc.ID, "reporting", "")
	var rep report.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, nil, nil, fmt.Errorf("parse report: %w", err)
	}
	return &rep, files, meta, nil
}

// collect copies the reports out of the stopped scan container.
func (w *Worker) collect(ctx context.Context, id string, files map[string][]byte) error {
	rc, err := w.docker.Archive(ctx, id, "/work/out")
	if err != nil {
		return fmt.Errorf("read reports: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return extractReports(rc, files)
}

// extractReports reads the known report files from a tar stream of out/.
func extractReports(r io.Reader, files map[string][]byte) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read reports: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		dir, name := path.Split(path.Clean(h.Name))
		if strings.Count(strings.Trim(dir, "/"), "/") > 0 {
			continue // raw/… tool outputs
		}
		format, ok := reportFiles[name]
		if !ok {
			continue
		}
		if h.Size > maxReportBytes {
			return fmt.Errorf("report %s is too large (%d bytes)", name, h.Size)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxReportBytes))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		files[format] = b
	}
}

func gz(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// persist stores tools, issues (new / existing / fixed), reports and the
// summary in one transaction, then notifies.
func (w *Worker) persist(ctx context.Context, sc *db.Scan, p *db.Project, rep *report.Report, files map[string][]byte, meta *fetchMeta) error {
	sum := service.ScanSummary{Counts: rep.Summary, Gate: rep.Gate, Warnings: rep.Warnings, DurationSec: rep.DurationSec, SizeMB: meta.sizeMB}
	if rep.Detected != nil {
		sum.Languages = rep.Detected.Languages
	}
	sumJSON, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	compressed := map[string][]byte{}
	for f, b := range files {
		if compressed[f], err = gz(b); err != nil {
			return err
		}
	}
	var newCount, fixedCount int
	scope := store.Scope{OrgID: sc.OrgID}
	err = w.db.Tx(ctx, scope, func(q *db.Queries) error {
		for _, t := range rep.Tools {
			if err := q.InsertScanTool(ctx, db.InsertScanToolParams{
				ID: newID(), OrgID: sc.OrgID, ScanID: sc.ID, ToolID: t.ID, Name: t.Name, ToolVersion: t.Version,
				Status: t.Status, DurationMs: t.DurationMS, FindingsCount: int32(min(t.Findings, 1<<30)), //nolint:gosec // bounded
				Error: trunc(t.Error, 2000),
			}); err != nil {
				return err
			}
		}
		for i := range rep.Issues {
			is := &rep.Issues[i]
			detail, err := json.Marshal(is)
			if err != nil {
				return err
			}
			cve := is.CVE
			if cve == nil {
				cve = []string{}
			}
			cwe := is.CWE
			if cwe == nil {
				cwe = []string{}
			}
			row, err := q.UpsertIssue(ctx, db.UpsertIssueParams{
				ID: newID(), OrgID: sc.OrgID, ProjectID: p.ID, Fingerprint: is.Fingerprint, Category: string(is.Category),
				Severity: is.Severity.String(), Title: trunc(is.Title, 500), RuleID: trunc(ruleID(is), 300),
				File: trunc(is.File, 1000), StartLine: int32(min(is.StartLine, 1<<30)), //nolint:gosec // bounded
				Cwe: cwe, Cve: cve, Sources: is.Sources, Detail: detail, FirstSeenScanID: &sc.ID,
			})
			if err != nil {
				return fmt.Errorf("upsert issue: %w", err)
			}
			if row.Inserted {
				newCount++
			}
			if err := q.InsertScanIssue(ctx, db.InsertScanIssueParams{ScanID: sc.ID, IssueID: row.ID, OrgID: sc.OrgID, IsNew: row.Inserted}); err != nil {
				return err
			}
		}
		// Issues missing from a complete scan of the main branch are fixed.
		// Partial scans or other branches cannot prove an issue is gone.
		if !rep.Partial && sc.Branch == service.DefaultBranch(p) {
			n, err := q.MarkMissingIssuesFixed(ctx, db.MarkMissingIssuesFixedParams{ScanID: sc.ID, ProjectID: p.ID})
			if err != nil {
				return err
			}
			fixedCount = int(n)
		}
		for format, b := range compressed {
			if err := q.InsertReport(ctx, db.InsertReportParams{ID: newID(), OrgID: sc.OrgID, ScanID: sc.ID, Format: format, ContentGz: b}); err != nil {
				return err
			}
		}
		gate := rep.Gate.Result
		score := int32(rep.Score) //nolint:gosec // 0..100
		reason := ""
		if rep.Partial {
			reason = "Some scanners failed; results are partial."
		}
		return q.FinishScan(ctx, db.FinishScanParams{
			ID: sc.ID, Status: "completed", StatusReason: reason, Partial: rep.Partial, Summary: sumJSON,
			GateResult: &gate, Score: &score, NewIssues: int32(newCount), FixedIssues: int32(fixedCount), //nolint:gosec // counts
		})
	})
	if err != nil {
		return err
	}
	msg := w.message(ctx, sc, p, notify.EventScanCompleted)
	msg.Gate, msg.Score, msg.New, msg.Fixed = rep.Gate.Result, rep.Score, newCount, fixedCount
	msg.Critical, msg.High, msg.Medium, msg.Low = rep.Summary.Critical, rep.Summary.High, rep.Summary.Medium, rep.Summary.Low
	w.notify(ctx, sc.OrgID, msg, rep.Gate.Result == "fail")
	return nil
}

func ruleID(is *finding.Issue) string {
	if len(is.Findings) > 0 {
		return is.Findings[0].RuleID
	}
	return ""
}

func newID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New()
	}
	return id
}

func (w *Worker) failScan(ctx context.Context, sc *db.Scan, p *db.Project, code, reason string) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	sum, _ := json.Marshal(service.ScanSummary{FailureCode: code})
	_ = w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		return q.FinishScan(fctx, db.FinishScanParams{ID: sc.ID, Status: "failed", StatusReason: trunc(reason, 2000), Summary: sum})
	})
	msg := w.message(fctx, sc, p, notify.EventScanFailed)
	msg.Reason = friendlyGitError(code, reason)
	w.notify(fctx, sc.OrgID, msg, false)
}

func (w *Worker) message(ctx context.Context, sc *db.Scan, p *db.Project, event string) notify.Message {
	m := notify.Message{Event: event, Project: p.Name, Branch: sc.Branch, Commit: sc.CommitSha}
	_ = w.db.Tx(ctx, superadmin, func(q *db.Queries) error {
		o, err := q.GetOrgByID(ctx, sc.OrgID)
		if err != nil {
			return err
		}
		m.Org = o.Name
		if w.cfg.BaseURL != "" {
			m.URL = strings.TrimRight(w.cfg.BaseURL, "/") + "/o/" + o.Slug + "/scans/" + sc.ID.String()
		}
		return nil
	})
	return m
}

// notify sends m to every channel of the org subscribed to its event (and
// to gate.failed when the gate failed). Failures are logged, never retried
// endlessly.
func (w *Worker) notify(ctx context.Context, orgID uuid.UUID, m notify.Message, gateFailed bool) {
	if w.notifier == nil {
		return
	}
	var chans []db.NotificationChannel
	_ = w.db.Tx(ctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
		var err error
		chans, err = q.ListNotificationChannels(ctx, orgID)
		return err
	})
	for _, ch := range chans {
		send := false
		event := m.Event
		for _, e := range ch.Events {
			if e == m.Event {
				send = true
			}
			if gateFailed && e == notify.EventGateFailed {
				send, event = true, notify.EventGateFailed
			}
		}
		if !send {
			continue
		}
		target, err := w.box.Open(ch.TargetEnc, ch.Nonce, service.ChannelAAD(ch.ID))
		if err != nil {
			w.log.Error("decrypt notification channel", "channel", ch.ID, "err", err)
			continue
		}
		msg := m
		msg.Event = event
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		if err := w.notifier.Send(sctx, ch.Kind, string(target), msg); err != nil {
			w.log.Warn("notification failed", "channel", ch.ID, "kind", ch.Kind, "err", err)
		}
		cancel()
	}
}
