package gitleaks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/scannertest"
)

// fixtureValue is a FAKE credential, split so secret scanners do not flag
// this test source. It grants access to nothing.
var fixtureValue = "Zx9fQ2LmP7" + "rT4vW8yB1nK6sD3hJ5"

func TestParseGolden(t *testing.T) {
	cases := []struct {
		mode  Mode
		input string
		n     int
	}{
		{ModeDir, "gitleaks/dir.json", 1},
		{ModeGit, "gitleaks/git.json", 1},
		{ModeDir, "gitleaks/empty.json", 0},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			fs, err := Scanner{Mode: c.mode}.parse(scannertest.Input(t, c.input))
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != c.n {
				t.Fatalf("findings %d want %d", len(fs), c.n)
			}
			finding.Normalize(fs, finding.NormalizeOptions{})
			scannertest.Golden(t, strings.TrimSuffix(c.input, ".json")+".expected.json", fs)
			raw, _ := json.Marshal(fs)
			for _, secret := range []string{fixtureValue + "qWq", "Qm7Xv2Lp9Tz4" + "Rk8Wn1Bs6Jd3Hf5Yc0Ge"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("plaintext secret in findings")
				}
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := (Scanner{Mode: ModeDir}).parse([]byte("{not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDirAndGitShareFingerprintAndHistoryIsDowngraded(t *testing.T) {
	dir := Scanner{Mode: ModeDir}
	git := Scanner{Mode: ModeGit}
	d, _ := dir.parse([]byte(`[{"RuleID":"generic-api-key","File":"/work/src/a.php","StartLine":3,"EndLine":3,"Match":"k = \"REDACTED\""}]`))
	g, _ := git.parse([]byte(`[{"RuleID":"generic-api-key","File":"a.php","Commit":"0123456789abcdef","Match":"k = \"REDACTED\""},
		{"RuleID":"aws-access-token","File":"old.php","Commit":"fedcba9876543210","Match":"AKIA-REDACTED"}]`))
	all := git.PostProcess(append(d, g...))
	if len(all) != 2 {
		t.Fatalf("duplicate history finding not dropped: %+v", all)
	}
	for _, f := range all {
		if f.File == "old.php" && f.Severity != finding.Medium {
			t.Fatalf("history-only secret must be medium, got %v", f.Severity)
		}
	}
	if dir.PostProcess(all) == nil {
		t.Fatal("dir PostProcess must be identity")
	}
}

func TestCommandAndApplies(t *testing.T) {
	env := scanner.Env{SourceDir: "/work/src", OutDir: "/out", ConfigDir: "/cfg"}
	c := Scanner{Mode: ModeGit}.Command(env, scanner.Settings{})
	joined := strings.Join(c.Args, " ")
	for _, want := range []string{"git /work/src", "-c /cfg/gitleaks.toml", "--redact", "--exit-code 0", "--log-opts=--all"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if len(c.Env) == 0 {
		t.Error("git mode needs safe.directory env")
	}
	gitS := Scanner{Mode: ModeGit}
	if gitS.Applies(&detect.Result{}, scanner.Settings{History: true}) {
		t.Error("git mode must not apply without .git")
	}
	if !gitS.Applies(&detect.Result{HasGit: true}, scanner.Settings{History: true}) {
		t.Error("git mode must apply with .git and history on")
	}
	if gitS.Applies(&detect.Result{HasGit: true}, scanner.Settings{History: true, Profile: "fast"}) {
		t.Error("fast profile skips history")
	}
}
