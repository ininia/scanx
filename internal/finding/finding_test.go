package finding

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fixtureValue is a FAKE credential, split so secret scanners do not flag
// this test source. It grants access to nothing.
var fixtureValue = "Zx9fQ2LmP7" + "rT4vW8yB1nK6sD3hJ5"

func TestSeverityTextRoundTrip(t *testing.T) {
	for s := Info; s <= Critical; s++ {
		b, _ := s.MarshalText()
		var got Severity
		if err := got.UnmarshalText(b); err != nil || got != s {
			t.Fatalf("%v round trip → %v, %v", s, got, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected error")
	}
	if Severity(99).String() != "info" {
		t.Fatal("out of range should be info")
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"HIGH"`), &s); err != nil || s != High {
		t.Fatalf("json: %v %v", s, err)
	}
}

func TestSeverityMappings(t *testing.T) {
	sarif := map[string]Severity{"error": High, "warning": Medium, "note": Low, "none": Info, "": Info}
	for in, want := range sarif {
		if got := FromSARIFLevel(in); got != want {
			t.Errorf("sarif %q = %v want %v", in, got, want)
		}
	}
	cvss := map[float64]Severity{9.8: Critical, 9.0: Critical, 7.5: High, 7.0: High, 5.3: Medium, 4.0: Medium, 3.9: Low, 0.1: Low, 0: Info}
	for in, want := range cvss {
		if got := FromCVSS(in); got != want {
			t.Errorf("cvss %v = %v want %v", in, got, want)
		}
	}
	vendor := map[string]Severity{"CRITICAL": Critical, "high": High, "Moderate": Medium, "LOW": Low, "negligible": Info}
	for in, want := range vendor {
		if got, ok := FromVendor(in); !ok || got != want {
			t.Errorf("vendor %q = %v,%v", in, got, ok)
		}
	}
	if _, ok := FromVendor("UNKNOWN"); ok {
		t.Error("UNKNOWN must not be recognized")
	}
}

func TestSecretSeverity(t *testing.T) {
	cases := []struct {
		rule    string
		history bool
		want    Severity
	}{
		{"aws-access-token", false, Critical},
		{"private-key", false, Critical},
		{"github-pat", false, Critical},
		{"generic-api-key", false, High},
		{"aws-access-token", true, Medium},
	}
	for _, c := range cases {
		if got := SecretSeverity(c.rule, c.history); got != c.want {
			t.Errorf("%s/%v = %v want %v", c.rule, c.history, got, c.want)
		}
	}
}

func TestNormalizeCWEsAndOWASP(t *testing.T) {
	got := NormalizeCWEs("CWE-89: Improper Neutralization", "cwe_079", "CWE-89", "nothing")
	if strings.Join(got, ",") != "CWE-89,CWE-79" {
		t.Fatalf("cwes %v", got)
	}
	if o := NormalizeOWASP("A03:2021 - Injection", "A03:2021", "A1"); len(o) != 1 || o[0] != "A03:2021" {
		t.Fatalf("owasp %v", o)
	}
}

func TestMasking(t *testing.T) {
	if MaskSecret("abcdefghijk") != "abc***" || MaskSecret("short") != "***" {
		t.Fatal("MaskSecret")
	}
	line := `$apiKey = "` + fixtureValue + `"; // FAKE`
	masked := MaskLine(line)
	if strings.Contains(masked, fixtureValue) || !strings.Contains(masked, `"Zx9***"`) {
		t.Fatalf("not masked: %s", masked)
	}
	plain := "function getUserById(connection) { return lookup; }"
	if MaskLine(plain) != plain {
		t.Fatalf("ordinary code altered: %s", MaskLine(plain))
	}
	if !strings.Contains(MaskText("a\n"+line), "Zx9***") {
		t.Fatal("MaskText")
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSnippet(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 20; i++ {
		b.WriteString("line")
		b.WriteString(strings.Repeat("x", i%3))
		b.WriteString("\n")
	}
	root := writeTree(t, map[string]string{"src/a.php": b.String(), "bin.dat": "ab\x00cd"})
	snip, match, err := Snippet(root, "src/a.php", 10, 11, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(snip, "\n")); got != 8 {
		t.Fatalf("snippet lines %d: %q", got, snip)
	}
	if len(strings.Split(match, "\n")) != 2 {
		t.Fatalf("match %q", match)
	}
	if s, _, err := Snippet(root, "bin.dat", 1, 1, 3); err != nil || s != "" {
		t.Fatalf("binary: %q %v", s, err)
	}
	if s, _, _ := Snippet(root, "src/a.php", 0, 0, 3); s != "" {
		t.Fatal("line 0 should give nothing")
	}
}

func TestSafeJoinRejectsEscapes(t *testing.T) {
	outside := writeTree(t, map[string]string{"secret.txt": "FAKE host secret"})
	root := writeTree(t, map[string]string{"ok.txt": "fine"})
	for _, p := range []string{"../secret.txt", "../../etc/passwd", "a/../../x"} {
		if _, err := SafeJoin(root, p); err == nil {
			// "a/../../x" cleans to "/x" under root → does not exist; must still error
			t.Errorf("%q: expected error", p)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
			t.Fatal(err)
		}
		if _, err := SafeJoin(root, "link.txt"); !errors.Is(err, ErrOutsideRoot) {
			t.Fatalf("symlink escape not rejected: %v", err)
		}
		if _, _, err := Snippet(root, "link.txt", 1, 1, 0); err == nil {
			t.Fatal("snippet followed escaping symlink")
		}
	}
	if p, err := SafeJoin(root, "/ok.txt"); err != nil || !strings.HasSuffix(p, "ok.txt") {
		t.Fatalf("leading slash should be relative: %v %v", p, err)
	}
}

func TestFingerprintStableAcrossLineMoves(t *testing.T) {
	a := Finding{Tool: "opengrep", RuleID: "opt.scanx.rules.php.sqli", Category: CategorySAST, File: "a.php", StartLine: 10}
	a.SetMatchLines(`  $q = "SELECT * FROM u WHERE id=" . $_GET['id'];`)
	b := a
	b.StartLine = 42
	b.SetMatchLines(`$q  =  "SELECT * FROM u WHERE id=" . $_GET['id'];  `)
	if Fingerprint(&a) != Fingerprint(&b) {
		t.Fatal("fingerprint changed with line/whitespace")
	}
	c := a
	c.Tool = "semgrep"
	c.RuleID = "other.prefix.sqli"
	if Fingerprint(&a) != Fingerprint(&c) {
		t.Fatal("opengrep and semgrep with same rule leaf should match")
	}
	d := a
	d.SetMatchLines(`$q = "SELECT * FROM u WHERE name=" . $_GET['n'];`)
	if Fingerprint(&a) == Fingerprint(&d) {
		t.Fatal("different code must differ")
	}
	e := a
	e.File = "b.php"
	if Fingerprint(&a) == Fingerprint(&e) {
		t.Fatal("different file must differ")
	}
}

func TestFingerprintSCAAndSecretAreToolAgnostic(t *testing.T) {
	pkg := &PackageRef{Name: "guzzlehttp/guzzle", Version: "7.4.0", Ecosystem: "Packagist"}
	t1 := Finding{Tool: "trivy", Category: CategorySCA, RuleID: "CVE-2022-29248", CVE: []string{"CVE-2022-29248"}, Package: pkg, File: "composer.lock"}
	o1 := Finding{Tool: "osv-scanner", Category: CategorySCA, RuleID: "GHSA-cwmx-hcrq-mhc3", CVE: []string{"CVE-2022-29248", "GHSA-cwmx-hcrq-mhc3"}, Package: pkg, File: "composer.lock"}
	if Fingerprint(&t1) != Fingerprint(&o1) {
		t.Fatal("same CVE/package from two tools must share fingerprint")
	}
	s1 := Finding{Tool: "gitleaks", Category: CategorySecret, RuleID: "generic-api-key", File: "config.php"}
	s1.SetMatchLines(`$k = "Zx9***";`)
	s2 := Finding{Tool: "trivy", Category: CategorySecret, RuleID: "generic", File: "config.php"}
	s2.SetMatchLines(`$k = "Zx9***";`)
	if Fingerprint(&s1) != Fingerprint(&s2) {
		t.Fatal("same secret from two tools must share fingerprint")
	}
}

func TestGroup(t *testing.T) {
	sql1 := Finding{Tool: "opengrep", RuleID: "r.sqli", Category: CategorySAST, Severity: Medium, Title: "SQLi (opengrep)", File: "a.php", StartLine: 10, CWE: []string{"CWE-89"}, Fingerprint: "f1"}
	sql2 := Finding{Tool: "psalm", RuleID: "TaintedSql", Category: CategorySAST, Severity: High, Title: "SQLi (psalm)", File: "a.php", StartLine: 11, CWE: []string{"CWE-89"}, Fingerprint: "f2"}
	far := Finding{Tool: "opengrep", RuleID: "r.sqli", Category: CategorySAST, Severity: Medium, Title: "SQLi far", File: "a.php", StartLine: 50, CWE: []string{"CWE-89"}, Fingerprint: "f3"}
	pkg := &PackageRef{Name: "x", Version: "1"}
	v1 := Finding{Tool: "trivy", Category: CategorySCA, RuleID: "CVE-1", CVE: []string{"CVE-1"}, Package: pkg, Severity: Critical, Fingerprint: "f4", Title: "CVE-1 trivy"}
	v2 := Finding{Tool: "osv-scanner", Category: CategorySCA, RuleID: "GHSA-1", CVE: []string{"GHSA-1", "CVE-1"}, Package: pkg, Severity: High, Fingerprint: "f5", Title: "CVE-1 osv"}
	dup := sql1
	dup.Tool = "semgrep"

	issues := Group([]Finding{sql1, sql2, far, v1, v2, dup})
	if len(issues) != 3 {
		t.Fatalf("want 3 issues, got %d: %+v", len(issues), issues)
	}
	if issues[0].Category != CategorySCA || issues[0].Severity != Critical ||
		strings.Join(issues[0].Sources, ",") != "osv-scanner,trivy" || issues[0].Title != "CVE-1 trivy" || issues[0].Confidence != "high" {
		t.Fatalf("sca issue wrong: %+v", issues[0])
	}
	if issues[1].Severity != High || len(issues[1].Findings) != 3 || strings.Join(issues[1].Sources, ",") != "opengrep,psalm,semgrep" {
		t.Fatalf("merged sqli wrong: %+v", issues[1])
	}
	if issues[2].StartLine != 50 || len(issues[2].Findings) != 1 {
		t.Fatalf("far finding wrong: %+v", issues[2])
	}
	if Group(nil) == nil || len(Group(nil)) != 0 {
		t.Fatal("empty input → empty, non-nil slice")
	}
}

func TestNormalize(t *testing.T) {
	root := writeTree(t, map[string]string{
		"app/config.php": "<?php\n// config\n$apiKey = \"" + fixtureValue + "\"; // FAKE\n$debug = true;\n",
		"app/db.php":     "<?php\n$id = $_GET['id'];\n$q = \"SELECT * FROM users WHERE id=\" . $id;\nmysqli_query($c, $q);\n",
	})
	fs := []Finding{
		{
			Tool: "gitleaks", RuleID: "generic-api-key", Category: CategorySecret, File: "/work/src/app/config.php", StartLine: 3,
			Title: "Generic API Key " + fixtureValue, Raw: json.RawMessage(`{"Secret":"` + fixtureValue + `"}`),
		},
		{Tool: "opengrep", RuleID: "x.sqli", Category: CategorySAST, File: "./app/db.php", StartLine: 3, Title: strings.Repeat("t", 400)},
	}
	Normalize(fs, NormalizeOptions{SourceRoot: root, StoreSnippets: true})
	all, _ := json.Marshal(fs)
	if strings.Contains(string(all), fixtureValue) {
		t.Fatalf("secret leaked after normalize: %s", all)
	}
	if fs[0].File != "app/config.php" || fs[1].File != "app/db.php" {
		t.Fatalf("paths: %q %q", fs[0].File, fs[1].File)
	}
	if !strings.Contains(fs[1].Snippet, "SELECT * FROM users") || fs[1].Fingerprint == "" || fs[0].Fingerprint == "" {
		t.Fatalf("snippet/fingerprint missing: %+v", fs[1])
	}
	if len([]rune(fs[1].Title)) != 301 {
		t.Fatalf("title not clamped: %d", len([]rune(fs[1].Title)))
	}

	noSnip := []Finding{{Tool: "opengrep", RuleID: "x.sqli", Category: CategorySAST, File: "app/db.php", StartLine: 3}}
	Normalize(noSnip, NormalizeOptions{SourceRoot: root, StoreSnippets: false})
	if noSnip[0].Snippet != "" || noSnip[0].Fingerprint != fs[1].Fingerprint {
		t.Fatalf("snippets disabled must still fingerprint identically: %+v", noSnip[0])
	}
}

// Regression: a SAST finding on a line that contains a credential must not
// expose the credential in its snippet (found with real opengrep output).
func TestNormalizeMasksSecretsInNonSecretSnippets(t *testing.T) {
	root := writeTree(t, map[string]string{"cfg.php": "<?php\n$token = \"" + fixtureValue + "qWq\"; // TODO rotate\n"})
	fs := []Finding{{Tool: "opengrep", RuleID: "raptor-bad-words", Category: CategorySAST, File: "cfg.php", StartLine: 2}}
	Normalize(fs, NormalizeOptions{SourceRoot: root, StoreSnippets: true})
	if strings.Contains(fs[0].Snippet, fixtureValue+"qWq") || !strings.Contains(fs[0].Snippet, "Zx9***") {
		t.Fatalf("snippet not masked: %q", fs[0].Snippet)
	}
}

func TestCleanRel(t *testing.T) {
	cases := map[string]string{
		"/work/src/a/b.go": "a/b.go", "./a/b.go": "a/b.go", "a/../../b": "b",
		"file:///work/src/x.tf": "x.tf", "": "",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q)=%q want %q", in, got, want)
		}
	}
}

// Tools such as gitleaks provide their own redacted match (the fingerprint
// identity); the line is still read for display, masked.
func TestSecretSnippetShownMasked(t *testing.T) {
	root := t.TempDir()
	secret := "5c06e1f0b2a94d7c" + "8e3f6a1b9d2c4e7f" // FAKE, split so secret scanners skip it
	if err := os.WriteFile(filepath.Join(root, "Seed.cs"), []byte("var u = new User {\n  Password = \""+secret+"\",\n};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := Finding{Tool: "gitleaks", RuleID: "generic-api-key", Category: CategorySecret, File: "Seed.cs", StartLine: 2, EndLine: 2}
	f.SetMatchLines("Password = \"REDACTED\"")
	fs := []Finding{f}
	Normalize(fs, NormalizeOptions{SourceRoot: root, StoreSnippets: true})
	if !strings.Contains(fs[0].Snippet, "Password = \"5c0***\"") || strings.Contains(fs[0].Snippet, secret) {
		t.Fatalf("snippet %q", fs[0].Snippet)
	}
}

func TestNormalizeRelativizesToSourceRoot(t *testing.T) {
	fs := []Finding{{Tool: "gitleaks", RuleID: "r", Category: CategorySAST, File: "/tmp/scanx-1/changed/src/App/a.cs"}}
	Normalize(fs, NormalizeOptions{SourceRoot: "/tmp/scanx-1/changed"})
	if fs[0].File != "src/App/a.cs" {
		t.Fatalf("file %q", fs[0].File)
	}
}
