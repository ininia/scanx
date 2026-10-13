package extra

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// Language tools must only run on their own language: a .NET repository
// never gets gosec, Ruff or Psalm.
func TestLanguageToolsFollowDetection(t *testing.T) {
	dotnet := &detect.Result{Languages: map[string]int{"csharp": 120, "javascript": 30}}
	goRepo := &detect.Result{Languages: map[string]int{"go": 40}}
	php := &detect.Result{Languages: map[string]int{"php": 12}}
	py := &detect.Result{Languages: map[string]int{"python": 3}}
	cases := []struct {
		sc  scanner.Scanner
		on  *detect.Result
		off []*detect.Result
	}{
		{Gosec{}, goRepo, []*detect.Result{dotnet, php, py}},
		{Psalm{}, php, []*detect.Result{dotnet, goRepo, py}},
		{Ruff{}, py, []*detect.Result{dotnet, goRepo, php}},
	}
	for _, c := range cases {
		if !c.sc.Applies(c.on, scanner.Settings{}) {
			t.Errorf("%s should run for %v", c.sc.ID(), c.on.Languages)
		}
		for _, d := range c.off {
			if c.sc.Applies(d, scanner.Settings{}) {
				t.Errorf("%s must not run for %v", c.sc.ID(), d.Languages)
			}
		}
	}
	for _, sc := range scanner.Select(dotnet, scanner.Settings{}) {
		switch sc.ID() {
		case "gosec", "psalm", "ruff", "bandit":
			t.Errorf("%s selected for a .NET repository", sc.ID())
		}
	}
}

func TestGosecSeverity(t *testing.T) {
	out := t.TempDir()
	doc := `{"runs":[{"tool":{"driver":{"name":"gosec","rules":[
	 {"id":"G204","name":"x","shortDescription":{"text":"Subprocess launched with variable"},"properties":{"precision":"high","tags":["security","MEDIUM"]}},
	 {"id":"G101","name":"y","shortDescription":{"text":"Hardcoded credentials"},"properties":{"precision":"low","tags":["security","HIGH"]}}]}},
	 "results":[{"ruleId":"G204","level":"warning","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"cmd/a.go"},"region":{"startLine":3}}}]},
	            {"ruleId":"G101","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"cfg.go"},"region":{"startLine":9}}}]}]}]}`
	_ = os.WriteFile(filepath.Join(out, "gosec-modules.txt"), []byte(".\nsvc/api\n"), 0o600)
	_ = os.WriteFile(filepath.Join(out, "gosec-2.sarif"), []byte(doc), 0o600) // module 1 produced no report
	fs, err := Gosec{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 2 || fs[0].Severity != finding.Medium || fs[1].Severity != finding.Medium || fs[0].File != "svc/api/cmd/a.go" {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestGosecRunsPerModule(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	env := scanner.Env{SourceDir: src, OutDir: out, TmpDir: t.TempDir()}
	if c := (Gosec{}).Command(env, scanner.Settings{}); c.Path != "true" {
		t.Fatalf("no go.mod should be a no-op: %+v", c)
	}
	for _, d := range []string{"svc", "tools/gen", "testdata/fixture", "vendor/x"} {
		_ = os.MkdirAll(filepath.Join(src, d), 0o750)
		_ = os.WriteFile(filepath.Join(src, d, "go.mod"), []byte("module x\n"), 0o600)
	}
	c := Gosec{}.Command(env, scanner.Settings{})
	if c.Path != "scanx-gosec" || len(c.Args) != 3 || c.Args[0] != out || !strings.Contains(strings.Join(c.Env, " "), "GOPROXY=off") {
		t.Fatalf("%+v", c)
	}
	mods, _ := os.ReadFile(filepath.Join(out, "gosec-modules.txt"))
	if string(mods) != "svc\ntools/gen\n" {
		t.Fatalf("modules %q", mods)
	}
}

func TestPsalmConfigAndPaths(t *testing.T) {
	src, out, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(src, "vendor", "x"), 0o750)
	_ = os.MkdirAll(filepath.Join(src, "app"), 0o750)
	env := scanner.Env{SourceDir: src, OutDir: out, TmpDir: tmp}
	c := Psalm{}.Command(env, scanner.Settings{})
	cfg, err := os.ReadFile(filepath.Join(tmp, "psalm.xml"))
	if err != nil || c.Path != "psalm" {
		t.Fatalf("%v %+v", err, c)
	}
	if !strings.Contains(string(cfg), filepath.Join(src, "vendor")) || strings.Contains(string(cfg), filepath.Join(src, "app")) {
		t.Fatalf("config:\n%s", cfg)
	}
	doc := `{"runs":[{"tool":{"driver":{"name":"Psalm","rules":[{"id":"244","name":"TaintedSql","shortDescription":{"text":"TaintedSql"}},
	 {"id":"245","name":"TaintedHtml","shortDescription":{"text":"TaintedHtml"}}]}},
	 "results":[{"ruleId":"244","message":{"text":"Detected tainted SQL"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"../../src/app/a.php"},"region":{"startLine":5}}}]},
	            {"ruleId":"245","message":{"text":"Detected tainted HTML"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.php"},"region":{"startLine":6}}}]}]}]}`
	_ = os.WriteFile(filepath.Join(out, "psalm.sarif"), []byte(doc), 0o600)
	fs, err := Psalm{}.Parse(env)
	if err != nil || len(fs) != 2 || fs[0].RuleID != "TaintedSql" || fs[0].Severity != finding.High || fs[1].Severity != finding.Medium {
		t.Fatalf("%+v %v", fs, err)
	}
	if want := filepath.Clean(filepath.Join(tmp, "psalm-root", "../../src/app/a.php")); fs[0].File != want {
		t.Fatalf("file %q want %q", fs[0].File, want)
	}
}

func TestActionlintAndSpectralParse(t *testing.T) {
	out := t.TempDir()
	al := `[{"message":"\"github.event.head_commit.message\" is potentially untrusted. avoid using it directly",` +
		`"filepath":".github/workflows/ci.yml","line":6,"column":24,"kind":"expression"}]`
	_ = os.WriteFile(filepath.Join(out, "actionlint.json"), []byte(al), 0o600)
	fs, err := Actionlint{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 1 || fs[0].RuleID != "actionlint.expression" || fs[0].Severity != finding.Medium || fs[0].StartLine != 6 {
		t.Fatalf("%+v %v", fs, err)
	}
	sp := `[
	 {"code":"owasp:api8:2023-no-server-http","message":"Server URLs must not use http://.","severity":0,"source":"/work/src/api.yaml","range":{"start":{"line":2},"end":{"line":2}}},
	 {"code":"owasp:api2:2023-read-restricted","message":"not protected","severity":1,"source":"/work/src/api.yaml","range":{"start":{"line":5},"end":{"line":7}}},
	 {"code":"invalid-ref","message":"remote","severity":0,"source":"/work/src/api.yaml","range":{"start":{"line":1},"end":{"line":1}}}]`
	_ = os.WriteFile(filepath.Join(out, "spectral.json"), []byte(sp), 0o600)
	fs, err = Spectral{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 2 || fs[0].Severity != finding.Medium || fs[1].Severity != finding.Medium || fs[0].StartLine != 3 {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestSpectralFindsSpecsByContent(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	env := scanner.Env{SourceDir: src, OutDir: out, ConfigDir: "/opt/scanx/config"}
	_ = os.WriteFile(filepath.Join(src, "values.yaml"), []byte("replicas: 2\n"), 0o600)
	if c := (Spectral{}).Command(env, scanner.Settings{}); c.Path != "true" {
		t.Fatalf("no spec should be a no-op: %+v", c)
	}
	_ = os.WriteFile(filepath.Join(src, "api-v1.yml"), []byte("openapi: 3.0.0\ninfo: {title: t}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(src, "legacy.json"), []byte("{\n  \"swagger\": \"2.0\"\n}\n"), 0o600)
	c := Spectral{}.Command(env, scanner.Settings{})
	args := strings.Join(c.Args, " ")
	if c.Path != "spectral" || !strings.Contains(args, "api-v1.yml") || !strings.Contains(args, "legacy.json") || strings.Contains(args, "values.yaml") {
		t.Fatalf("%+v", c)
	}
}

func TestKubeLinterSeverity(t *testing.T) {
	out := t.TempDir()
	loc := `"locations":[{"physicalLocation":{"artifactLocation":{"uri":"k8s/d.yaml"},"region":{"startLine":1}}}]`
	doc := `{"runs":[{"tool":{"driver":{"name":"kube-linter","rules":[]}},"results":[
	 {"ruleId":"privileged-container","level":"error","message":{"text":"m"},` + loc + `},
	 {"ruleId":"latest-tag","level":"error","message":{"text":"m"},` + loc + `},
	 {"ruleId":"run-as-non-root","level":"error","message":{"text":"m"},` + loc + `}]}]}`
	_ = os.WriteFile(filepath.Join(out, "kube-linter.sarif"), []byte(doc), 0o600)
	fs, err := KubeLinter{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 3 || fs[0].Severity != finding.High || fs[1].Severity != finding.Low || fs[2].Severity != finding.Medium ||
		fs[0].RuleID != "kube-linter.privileged-container" {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestActionlintSkipsWithoutWorkflows(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	if c := (Actionlint{}).Command(scanner.Env{SourceDir: src, OutDir: out}, scanner.Settings{}); c.Path != "true" {
		t.Fatalf("%+v", c)
	}
	_ = os.MkdirAll(filepath.Join(src, ".github", "workflows"), 0o750)
	_ = os.WriteFile(filepath.Join(src, ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o600)
	c := Actionlint{}.Command(scanner.Env{SourceDir: src, OutDir: out}, scanner.Settings{})
	if c.Path != "actionlint" || c.Dir != src || c.Args[len(c.Args)-1] != ".github/workflows/ci.yml" {
		t.Fatalf("%+v", c)
	}
}
