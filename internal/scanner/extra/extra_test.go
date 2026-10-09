package extra

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

func TestLizardThresholds(t *testing.T) {
	out := t.TempDir()
	csv := `NLOC,CCN,token,PARAM,length,location,file,function,long_name,start,end
10,3,50,1,12,"ok@1-12@a.cs","a.cs","Ok","Ok()",1,12
80,25,400,2,90,"Mid@20-110@a.cs","a.cs","Mid","Mid(a,b)",20,110
200,70,999,4,250,"Huge@200-450@b.cs","b.cs","Huge","Huge()",200,450
320,5,999,0,330,"Long@500-830@b.cs","b.cs","Long","Long()",500,830
`
	if err := os.WriteFile(filepath.Join(out, "lizard.csv"), []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := Lizard{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 3 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].Severity != finding.Low || fs[1].Severity != finding.High || fs[2].RuleID != "lizard.long-function" ||
		fs[0].Category != finding.CategoryQuality || fs[1].StartLine != 200 {
		t.Fatalf("%+v", fs)
	}
}

func TestShellCheckParse(t *testing.T) {
	out := t.TempDir()
	js := `{"comments":[{"file":"/work/src/a.sh","line":3,"endLine":3,"column":1,"level":"warning","code":2086,"message":"Double quote to prevent globbing"},
	{"file":"/work/src/a.sh","line":9,"endLine":9,"column":1,"level":"error","code":1009,"message":"parse error"}]}`
	_ = os.WriteFile(filepath.Join(out, "shellcheck.json"), []byte(js), 0o600)
	fs, err := ShellCheck{}.Parse(scanner.Env{OutDir: out})
	if err != nil || len(fs) != 2 || fs[0].RuleID != "SC2086" || fs[1].Severity != finding.Medium {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestCommandsSkipWhenNothingToCheck(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	env := scanner.Env{SourceDir: src, OutDir: out}
	for _, c := range []scanner.Cmd{Zizmor{}.Command(env, scanner.Settings{}), Hadolint{}.Command(env, scanner.Settings{}),
		ShellCheck{}.Command(env, scanner.Settings{})} {
		if c.Path != "true" || c.StdoutFile == "" {
			t.Fatalf("%+v", c)
		}
	}
	_ = os.MkdirAll(filepath.Join(src, ".github", "workflows"), 0o750)
	_ = os.MkdirAll(filepath.Join(src, "web", "node_modules", "x"), 0o750)
	_ = os.WriteFile(filepath.Join(src, "web", "Dockerfile"), []byte("FROM x"), 0o600)
	_ = os.WriteFile(filepath.Join(src, "web", "node_modules", "x", "Dockerfile"), []byte("FROM x"), 0o600)
	if c := (Zizmor{}).Command(env, scanner.Settings{}); c.Path != "zizmor" || !strings.Contains(strings.Join(c.Args, " "), "--offline") {
		t.Fatalf("zizmor must run offline: %+v", c)
	}
	c := Hadolint{}.Command(env, scanner.Settings{})
	if c.Path != "hadolint" || len(c.Args) != 4 || !strings.HasSuffix(c.Args[3], filepath.Join("web", "Dockerfile")) {
		t.Fatalf("hadolint files: %+v", c.Args)
	}
}
