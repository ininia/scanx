package service

import (
	"net/http"
	"testing"
)

func TestVerifyWebhook(t *testing.T) {
	secret := []byte("s3cret")
	body := []byte(`{"ref":"refs/heads/main"}`)
	sig := hmacHex(secret, body)
	cases := []struct {
		provider string
		h        http.Header
		want     bool
	}{
		{"github", http.Header{"X-Hub-Signature-256": {"sha256=" + sig}}, true},
		{"github", http.Header{"X-Hub-Signature-256": {"sha256=" + hmacHex([]byte("other"), body)}}, false},
		{"github", http.Header{}, false},
		{"gitea", http.Header{"X-Gitea-Signature": {sig}}, true},
		{"gitea", http.Header{"X-Forgejo-Signature": {sig}}, true},
		{"gitlab", http.Header{"X-Gitlab-Token": {"s3cret"}}, true},
		{"gitlab", http.Header{"X-Gitlab-Token": {"wrong"}}, false},
		{"bitbucket", http.Header{"X-Hub-Signature": {"sha256=" + sig}}, true},
		{"generic", http.Header{"X-Scanx-Signature": {"sha256=" + sig}}, true},
		{"generic", http.Header{"X-Scanx-Signature": {sig}}, false},
		{"unknown", http.Header{"X-Hub-Signature-256": {"sha256=" + sig}}, false},
	}
	for _, c := range cases {
		if got := verifyWebhook(c.provider, c.h, body, secret); got != c.want {
			t.Errorf("%s %v: got %v want %v", c.provider, c.h, got, c.want)
		}
	}
}

const testSHA = "0123456789abcdef0123456789abcdef01234567"

func TestParsePush(t *testing.T) {
	gh := `{"ref":"refs/heads/main","after":"` + testSHA + `","deleted":false,
	  "head_commit":{"id":"` + testSHA + `","message":"fix: x\n\nbody","author":{"name":"A","email":"a@x.io"}}}`
	ev, err := parsePush("github", []byte(gh))
	if err != nil || ev.Ref != "refs/heads/main" || ev.Commit != testSHA || ev.Message != "fix: x" || ev.Author != "A <a@x.io>" {
		t.Fatalf("github: %+v %v", ev, err)
	}
	gl := `{"ref":"refs/heads/dev","after":"` + testSHA + `","checkout_sha":"` + testSHA +
		`","commits":[{"id":"` + testSHA + `","message":"m","author":{"name":"B","email":""}}]}`
	ev, err = parsePush("gitlab", []byte(gl))
	if err != nil || ev.Ref != "refs/heads/dev" || ev.Author != "B" || ev.Deleted {
		t.Fatalf("gitlab: %+v %v", ev, err)
	}
	bb := `{"push":{"changes":[{"new":{"type":"branch","name":"main","target":{"hash":"` + testSHA +
		`","message":"m","author":{"raw":"C <c@x>"}}}}]}}`
	ev, err = parsePush("bitbucket", []byte(bb))
	if err != nil || ev.Ref != "refs/heads/main" || ev.Commit != testSHA {
		t.Fatalf("bitbucket: %+v %v", ev, err)
	}
	if _, err := parsePush("github", []byte(`{"ref":"refs/heads/main","after":"; rm -rf /"}`)); err == nil {
		t.Fatal("non-hex commit accepted")
	}
	ev, _ = parsePush("generic", []byte(`{"branch":"main","commit":"`+testSHA+`"}`))
	if ev.Ref != "refs/heads/main" {
		t.Fatalf("generic: %+v", ev)
	}
}

func TestBranchMatches(t *testing.T) {
	if !BranchMatches([]string{"main", "release/*"}, "release/1.2") || BranchMatches([]string{"main"}, "dev") {
		t.Fatal("branch patterns")
	}
}

func TestMaskTarget(t *testing.T) {
	if got := MaskTarget("slack", "https://hooks.slack.com/services/T0/B0/XYZ"); got != "https://hooks.slack.com/•••" {
		t.Fatal(got)
	}
}
