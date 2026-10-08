//go:build integration

package worker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/report"
	"github.com/ininia/scanx/internal/secret"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

func issue(fp string, sev finding.Severity) finding.Issue {
	return finding.Issue{
		Fingerprint: fp, Category: finding.CategorySAST, Severity: sev, Title: "T " + fp,
		File: "a.php", StartLine: 3, Sources: []string{"opengrep"},
		Findings: []finding.Finding{{Tool: "opengrep", RuleID: "r." + fp, Title: "T " + fp, Severity: sev}},
	}
}

func rep(issues ...finding.Issue) *report.Report {
	sum := report.Summarize(issues)
	p, _ := report.ParseFailOn("high")
	return &report.Report{Issues: issues, Summary: sum, Score: report.Score(sum), Gate: p.Evaluate(sum)}
}

// persist computes new / existing / fixed issues across scans and keeps
// triage decisions.
func TestPersistIssueLifecycle(t *testing.T) {
	admin, app := os.Getenv("SCANX_TEST_DATABASE_ADMIN_URL"), os.Getenv("SCANX_TEST_DATABASE_URL")
	if admin == "" || app == "" {
		t.Skip("integration DB not configured")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := store.Migrate(ctx, secret.Secret(admin), log); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, secret.Secret(app))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	box, _ := crypto.New(bytes.Repeat([]byte{9}, 32))
	d := &store.DB{Pool: pool}
	w := New(d, box, nil, nil, Config{}, log)

	orgID, projID := newID(), newID()
	slug := "w" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	var p db.Project
	err = d.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		if _, err := q.CreateOrg(ctx, db.CreateOrgParams{ID: orgID, Name: slug, Slug: slug}); err != nil {
			return err
		}
		p, err = q.CreateProject(ctx, db.CreateProjectParams{
			ID: projID, OrgID: orgID, Name: "p", Slug: "p",
			RepoUrl: "https://github.com/a/b.git", Provider: "github", AuthMode: "deploy_key", Branches: []string{"main"},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	newScan := func() *db.Scan {
		var sc db.Scan
		err := d.Tx(ctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
			var err error
			sc, err = q.CreateScan(ctx, db.CreateScanParams{ID: newID(), OrgID: orgID, ProjectID: projID, Trigger: "manual", Branch: "main"})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return &sc
	}
	files := map[string][]byte{"json": []byte(`{}`), "html": []byte("<html>")}
	meta := &fetchMeta{commit: "c"}

	s1 := newScan()
	if err := w.persist(ctx, s1, &p, rep(issue("A", finding.High), issue("B", finding.Medium)), files, meta); err != nil {
		t.Fatal(err)
	}
	s2 := newScan()
	if err := w.persist(ctx, s2, &p, rep(issue("A", finding.High), issue("C", finding.Low)), files, meta); err != nil {
		t.Fatal(err)
	}
	err = d.Tx(ctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
		got1, _ := q.GetScan(ctx, db.GetScanParams{OrgID: orgID, ID: s1.ID})
		got2, _ := q.GetScan(ctx, db.GetScanParams{OrgID: orgID, ID: s2.ID})
		if got1.Status != "completed" || got1.NewIssues != 2 || *got1.GateResult != "fail" {
			t.Errorf("scan1: %+v", got1)
		}
		if got2.NewIssues != 1 || got2.FixedIssues != 1 {
			t.Errorf("scan2 new=%d fixed=%d", got2.NewIssues, got2.FixedIssues)
		}
		issues, err := q.ListProjectIssues(ctx, db.ListProjectIssuesParams{OrgID: orgID, ProjectID: projID})
		if err != nil {
			return err
		}
		st := map[string]string{}
		for _, i := range issues {
			st[i.Fingerprint] = i.Status
		}
		if st["A"] != "open" || st["B"] != "fixed" || st["C"] != "open" {
			t.Errorf("statuses %v", st)
		}
		gz, err := q.GetReport(ctx, db.GetReportParams{OrgID: orgID, ScanID: s2.ID, Format: "html"})
		if err != nil || len(gz) == 0 {
			t.Errorf("report: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// B reappears → reopened, not duplicated.
	s3 := newScan()
	if err := w.persist(ctx, s3, &p, rep(issue("A", finding.High), issue("B", finding.Medium), issue("C", finding.Low)), files, meta); err != nil {
		t.Fatal(err)
	}
	_ = d.Tx(ctx, store.Scope{OrgID: orgID}, func(q *db.Queries) error {
		issues, _ := q.ListProjectIssues(ctx, db.ListProjectIssuesParams{OrgID: orgID, ProjectID: projID})
		if len(issues) != 3 {
			t.Errorf("issues: %d", len(issues))
		}
		for _, i := range issues {
			if i.Status != "open" {
				t.Errorf("%s: %s", i.Fingerprint, i.Status)
			}
		}
		return nil
	})
	// Another org cannot see these issues (RLS).
	_ = d.Tx(ctx, store.Scope{OrgID: newID()}, func(q *db.Queries) error {
		issues, _ := q.ListProjectIssues(ctx, db.ListProjectIssuesParams{OrgID: orgID, ProjectID: projID})
		if len(issues) != 0 {
			t.Errorf("RLS leak: %d issues", len(issues))
		}
		return nil
	})
}
