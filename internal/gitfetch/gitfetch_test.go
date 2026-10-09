package gitfetch

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestFromEnv(t *testing.T) {
	r, err := FromEnv(env(map[string]string{
		"SCANX_REPO_URL": "git@github.com:ininia/scanx.git", "SCANX_BRANCH": "main",
		"SCANX_SSH_KEY": base64.StdEncoding.EncodeToString([]byte("KEY")), "SCANX_FETCH_DEPTH": "50",
	}))
	if err != nil || r.Mode != ModeClone || string(r.SSHKey) != "KEY" || r.Depth != 50 || r.Dest != "/work/src" {
		t.Fatalf("%+v %v", r, err)
	}
	bad := []map[string]string{
		{"SCANX_REPO_URL": "file:///etc", "SCANX_BRANCH": "main"},
		{"SCANX_REPO_URL": "git@github.com:a/b.git", "SCANX_BRANCH": "--upload-pack=x"},
		{"SCANX_REPO_URL": "git@github.com:a/b.git", "SCANX_BRANCH": "a..b"},
		{"SCANX_REPO_URL": "git@github.com:a/b.git", "SCANX_BRANCH": "main", "SCANX_COMMIT": "HEAD~1"},
		{"SCANX_REPO_URL": "git@github.com:a/b.git", "SCANX_BRANCH": "main", "SCANX_FETCH_MODE": "push"},
	}
	for _, m := range bad {
		if _, err := FromEnv(env(m)); err == nil {
			t.Errorf("accepted %v", m)
		}
	}
}

func TestSSHNeedsKnownHost(t *testing.T) {
	r := &Request{Mode: ModeLsRemote, RepoURL: "git@git.example.com:a/b.git", SSHKey: []byte("k")}
	res := Run(t.Context(), r, t.TempDir(), &strings.Builder{})
	if res.OK || !strings.Contains(res.Error, "not trusted") {
		t.Fatalf("%+v", res)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"git@github.com: Permission denied (publickey).":     "auth",
		"Host key verification failed.":                      "host_key",
		"fatal: couldn't find remote ref refs/heads/nope":    "not_found",
		"ERROR: Repository not found.":                       "not_found",
		"fatal: unable to access: Could not resolve host: x": "git",
	}
	for msg, code := range cases {
		if got := classify(&gitError{msg: msg, err: errors.New("exit 128")}); got.Code != code {
			t.Errorf("%q → %s, want %s", msg, got.Code, code)
		}
	}
}

func TestParseResult(t *testing.T) {
	out := "noise\nSCANX_RESULT {\"ok\":true,\"commit\":\"abc\"}\n"
	r, err := ParseResult([]byte(out))
	if err != nil || !r.OK || r.Commit != "abc" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseResult([]byte("nothing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDiffListsChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "src")
	g := &git{
		env: []string{
			"HOME=" + tmp, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
		},
		stderr: &strings.Builder{}, dir: repo,
	}
	must := func(args ...string) string {
		out, err := g.run(t.Context(), args...)
		if err != nil {
			t.Fatal(args, err)
		}
		return strings.TrimSpace(out)
	}
	write := func(name, body string) {
		p := filepath.Join(repo, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.MkdirAll(repo, 0o750)
	must("init", "-q", ".")
	write("keep.cs", "a")
	write("old.cs", "b")
	write("edit.cs", "c")
	must("add", ".")
	must("commit", "-q", "-m", "one")
	base := must("rev-parse", "HEAD")
	write("edit.cs", "c2")
	write("dir/new file.js", "d")
	must("rm", "-q", "old.cs")
	must("add", ".")
	must("commit", "-q", "-m", "two")

	d := g.diff(t.Context(), &Request{BaseCommit: base, Dest: repo})
	if !d.OK || strings.Join(d.Changed, ",") != "dir/new file.js,edit.cs" || strings.Join(d.Deleted, ",") != "old.cs" {
		t.Fatalf("%+v", d)
	}
	list, err := os.ReadFile(filepath.Join(tmp, ChangedListFile))
	if err != nil || string(list) != "dir/new file.js\nedit.cs" {
		t.Fatalf("list %q %v", list, err)
	}
	if d := g.diff(t.Context(), &Request{BaseCommit: strings.Repeat("a", 40), Dest: repo}); d.OK || d.Reason == "" {
		t.Fatalf("unknown base must fall back: %+v", d)
	}
}
