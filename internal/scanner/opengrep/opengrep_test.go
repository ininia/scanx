package opengrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/scannertest"
)

func TestParseGolden(t *testing.T) {
	fs, err := parse(scannertest.Input(t, "opengrep/php-vuln.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Minimum expected scanX PHP rule hits on the fixture (spec §19 Faz 1 acceptance).
	want := map[string]bool{
		"scanx.php.scanx-php-sqli-taint": false, "scanx.php.scanx-php-xss-echo": false,
		"scanx.php.scanx-php-command-injection": false, "scanx.php.scanx-php-file-inclusion": false,
		"scanx.php.scanx-php-unserialize-user-input": false, "scanx.php.scanx-php-code-injection": false,
		"scanx.php.scanx-php-open-redirect": false, "scanx.php.scanx-php-weak-password-hash": false,
		"scanx.php.scanx-php-sqli-string-building": false,
	}
	for _, f := range fs {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
		if f.Category != finding.CategorySAST || f.File == "" || f.StartLine == 0 {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected rule %s not reported", id)
		}
	}
	var sqli finding.Finding
	for _, f := range fs {
		if f.RuleID == "scanx.php.scanx-php-sqli-taint" {
			sqli = f
		}
	}
	if sqli.Severity != finding.High || strings.Join(sqli.CWE, ",") != "CWE-89" || strings.Join(sqli.OWASP, ",") != "A03:2021" || sqli.Confidence != "high" {
		t.Fatalf("sqli mapping wrong: %+v", sqli)
	}
	finding.Normalize(fs, finding.NormalizeOptions{})
	scannertest.Golden(t, "opengrep/php-vuln.expected.json", fs)

	empty, err := parse(scannertest.Input(t, "opengrep/empty.json"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v %d", err, len(empty))
	}
	if _, err := parse([]byte("nope")); err == nil {
		t.Fatal("expected error for malformed json")
	}
}

func TestDisplayRuleAndHelpers(t *testing.T) {
	cases := map[string]string{
		"opt.scanx.rules.scanx.php.x":      "scanx.php.x",
		"opt.scanx.rules._full.elttam.a.b": "elttam.a.b",
		"rules.php.x":                      "php.x",
		"custom.id":                        "custom.id",
	}
	for in, want := range cases {
		if got := displayRule(in); got != want {
			t.Errorf("displayRule(%q)=%q want %q", in, got, want)
		}
	}
	if firstSentence("One. Two.") != "One." || len([]rune(firstSentence(strings.Repeat("a", 300)))) != 201 {
		t.Error("firstSentence")
	}
	var sl stringList
	_ = sl.UnmarshalJSON([]byte(`"CWE-1"`))
	if len(sl) != 1 {
		t.Error("string metadata")
	}
	_ = sl.UnmarshalJSON([]byte(`{"x":1}`))
	if sl != nil {
		t.Error("object metadata must be ignored")
	}
}

func TestCommandUsesLocalRulesAndProfiles(t *testing.T) {
	rules := t.TempDir()
	for _, d := range []string{"scanx", "gitlab", "_full/elttam"} {
		if err := os.MkdirAll(filepath.Join(rules, filepath.FromSlash(d)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	env := scanner.Env{SourceDir: "/work/src", OutDir: "/out", RulesDir: rules, ToolHome: "/opt/home"}
	def := strings.Join(Scanner{}.Command(env, scanner.Settings{}).Args, " ")
	if strings.Contains(def, "_full") || !strings.Contains(def, filepath.Join(rules, "scanx")) {
		t.Fatalf("default profile config wrong: %s", def)
	}
	full := strings.Join(Scanner{}.Command(env, scanner.Settings{Profile: "full"}).Args, " ")
	if !strings.Contains(full, "_full") {
		t.Fatalf("full profile must include audit rules: %s", full)
	}
	for _, banned := range []string{"--config auto", "--config p/", "--config r/"} {
		if strings.Contains(def, banned) {
			t.Fatalf("registry config %q must never be used", banned)
		}
	}
	for _, need := range []string{"--x-ignore-semgrepignore-files", "--exclude node_modules", "/work/src"} {
		if !strings.Contains(def, need) {
			t.Errorf("missing %q", need)
		}
	}
	c := Scanner{}.Command(env, scanner.Settings{})
	if len(c.Env) != 1 || c.Env[0] != "XDG_CACHE_HOME="+filepath.Join("/opt/home", ".cache") {
		t.Errorf("cache env %v", c.Env)
	}
}
