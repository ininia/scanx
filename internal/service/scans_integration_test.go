//go:build integration

package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

func pushBody(branch, commit string) []byte {
	return []byte(`{"ref":"refs/heads/` + branch + `","after":"` + commit + `","deleted":false,` +
		`"head_commit":{"id":"` + commit + `","message":"feat: x","author":{"name":"Dev","email":"dev@example.test"}}}`)
}

func githubHeaders(secret string, body []byte, delivery string) http.Header {
	return http.Header{
		"X-Github-Event":      {"push"},
		"X-Github-Delivery":   {delivery},
		"X-Hub-Signature-256": {"sha256=" + hmacHex([]byte(secret), body)},
	}
}

func TestProjectGetsDeployKeyAndWebhookSecret(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	p, err := s.CreateProject(ctx, o, ProjectInput{RepoURL: "git@github.com:acme/" + uniq("r") + ".git"}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.ProjectDeployKey(ctx, o, p.Slug)
	if err != nil || k == nil {
		t.Fatal(k, err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey)); err != nil {
		t.Fatalf("public key not in authorized_keys format: %v", err)
	}
	// The private key is stored encrypted and bound to the project.
	err = d.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		row, err := q.GetActiveSSHKey(ctx, db.GetActiveSSHKeyParams{OrgID: o.Org.ID, ProjectID: p.ID})
		if err != nil {
			return err
		}
		if strings.Contains(string(row.PrivateKeyEnc), "PRIVATE KEY") {
			t.Fatal("private key stored in plaintext")
		}
		pem, err := s.box.Open(row.PrivateKeyEnc, row.Nonce, DeployKeyAAD(p.ID))
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return err
		}
		if ssh.FingerprintSHA256(signer.PublicKey()) != k.Fingerprint {
			t.Fatal("fingerprint mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s.RotateDeployKey(ctx, o, p.Slug, Meta{})
	if err != nil || k2.Fingerprint == k.Fingerprint {
		t.Fatalf("rotate: %v %v", k2, err)
	}
	sec, err := s.WebhookSecret(ctx, o, p.Slug)
	if err != nil || len(sec) < 32 {
		t.Fatalf("secret %q %v", sec, err)
	}
}

func TestWebhookQueuesScan(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	p, err := s.CreateProject(ctx, o, ProjectInput{RepoURL: "git@github.com:acme/" + uniq("r") + ".git", Branches: []string{"main", "release/*"}}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.WebhookSecret(ctx, o, p.Slug)
	if err != nil {
		t.Fatal(err)
	}
	pid := p.ID.String()

	body := pushBody("main", testSHA)
	// Wrong signature → rejected, nothing queued.
	if _, err := s.HandleWebhook(ctx, "github", pid, githubHeaders("wrong", body, "d0"), body); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	// Unknown project → not found (no information leak).
	if _, err := s.HandleWebhook(ctx, "github", newID().String(), githubHeaders(secret, body, "d0"), body); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown project: %v", err)
	}
	res, err := s.HandleWebhook(ctx, "github", pid, githubHeaders(secret, body, "d1"), body)
	if err != nil || res.Result != "queued" || res.ScanID == nil || res.Status != http.StatusAccepted {
		t.Fatalf("push: %+v %v", res, err)
	}
	// Same delivery again → duplicate.
	if res, err := s.HandleWebhook(ctx, "github", pid, githubHeaders(secret, body, "d1"), body); err != nil || res.Result != "duplicate" {
		t.Fatalf("redelivery: %+v %v", res, err)
	}
	// Same commit, new delivery id → already queued (one active scan per commit).
	if res, err := s.HandleWebhook(ctx, "github", pid, githubHeaders(secret, body, "d2"), body); err != nil || res.Result != "already_queued" {
		t.Fatalf("same commit: %+v %v", res, err)
	}
	// Branch filter with glob.
	other := pushBody("feature/x", strings.Repeat("a", 40))
	if res, err := s.HandleWebhook(ctx, "github", pid, githubHeaders(secret, other, "d3"), other); err != nil || res.Result != "ignored_branch" {
		t.Fatalf("branch filter: %+v %v", res, err)
	}
	rel := pushBody("release/1.0", strings.Repeat("b", 40))
	if res, err := s.HandleWebhook(ctx, "github", pid, githubHeaders(secret, rel, "d4"), rel); err != nil || res.Result != "queued" {
		t.Fatalf("glob branch: %+v %v", res, err)
	}
	// Ping.
	ping := http.Header{"X-Github-Event": {"ping"}, "X-Github-Delivery": {"d5"}, "X-Hub-Signature-256": {"sha256=" + hmacHex([]byte(secret), []byte(`{}`))}}
	if res, err := s.HandleWebhook(ctx, "github", pid, ping, []byte(`{}`)); err != nil || res.Result != "pong" {
		t.Fatalf("ping: %+v %v", res, err)
	}

	// The queued scan carries the push metadata and has a job.
	scans, err := s.ListProjectScans(ctx, o, p, 10)
	if err != nil || len(scans) != 2 {
		t.Fatalf("scans: %d %v", len(scans), err)
	}
	var main *db.Scan
	for i := range scans {
		if scans[i].Branch == "main" {
			main = &scans[i]
		}
	}
	if main == nil || main.CommitSha != testSHA || main.Trigger != TriggerWebhook || main.CommitAuthor != "Dev <dev@example.test>" {
		t.Fatalf("scan: %+v", main)
	}
	err = d.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		n, err := q.CountQueuedJobs(ctx)
		if err == nil && n < 2 {
			t.Fatalf("jobs queued: %d", n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManualScanAndTenantIsolation(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	bob, _ := newUser(t, s, d, false)
	oa, ob := newOrg(t, s, alice), newOrg(t, s, bob)
	p, err := s.CreateProject(ctx, oa, ProjectInput{RepoURL: "https://github.com/acme/" + uniq("r") + ".git"}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := s.TriggerScan(ctx, oa, p.Slug, "", TriggerManual, Meta{})
	if err != nil || sc.Branch != "main" || sc.Status != "queued" {
		t.Fatalf("trigger: %+v %v", sc, err)
	}
	// A second click while queued returns the same scan.
	sc2, err := s.TriggerScan(ctx, oa, p.Slug, "main", TriggerManual, Meta{})
	if err != nil || sc2.ID != sc.ID {
		t.Fatalf("double click: %v %v", sc2, err)
	}
	if _, err := s.TriggerScan(ctx, oa, p.Slug, "--upload-pack=x", TriggerManual, Meta{}); err == nil {
		t.Fatal("option-like branch accepted")
	}
	// Bob's org cannot see Alice's scan, report or job.
	if _, err := s.GetScan(ctx, ob, sc.ID.String(), true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant scan: %v", err)
	}
	if _, err := s.ScanReport(ctx, ob, sc.ID.String(), "html"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant report: %v", err)
	}
	if err := s.CancelScan(ctx, ob, sc.ID.String(), Meta{}); err == nil {
		t.Fatal("cross-tenant cancel")
	}
	jobID, err := s.TestConnection(ctx, oa, p.Slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetJob(ctx, ob, jobID.String()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant job: %v", err)
	}
	if err := s.CancelScan(ctx, oa, sc.ID.String(), Meta{}); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetScan(ctx, oa, sc.ID.String(), false)
	if err != nil || v.Scan.Status != "canceled" {
		t.Fatalf("cancel: %+v %v", v, err)
	}
}

func TestNotificationChannels(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	if _, err := s.CreateChannel(ctx, o, "slack", "Ops", "http://10.0.0.1/hook", []string{"gate.failed"}, Meta{}); err == nil {
		t.Fatal("private/http slack URL accepted")
	}
	ch, err := s.CreateChannel(ctx, o, "slack", "Ops", "https://hooks.slack.com/services/T/B/SECRETPART", []string{"gate.failed", "bogus"}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ListChannels(ctx, o)
	if err != nil || len(list) != 1 || strings.Contains(list[0].Target, "SECRETPART") || len(list[0].Events) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := s.DeleteChannel(ctx, o, ch.ID.String(), Meta{}); err != nil {
		t.Fatal(err)
	}
}
