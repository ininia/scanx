package engine

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// fakeScanner is a configurable scanner.Scanner.
type fakeScanner struct {
	id       string
	findings []finding.Finding
	parseErr error
	timeout  time.Duration
	ok       []int
}

// fixtureValue is a FAKE credential, split so secret scanners do not flag
// this test source. It grants access to nothing.
var fixtureValue = "Zx9fQ2LmP7" + "rT4vW8yB1nK6sD3hJ5"

func (f fakeScanner) ID() string                                    { return f.id }
func (f fakeScanner) Name() string                                  { return "Fake " + f.id }
func (f fakeScanner) Tool() string                                  { return f.id }
func (f fakeScanner) Category() finding.Category                    { return finding.CategorySAST }
func (f fakeScanner) Applies(*detect.Result, scanner.Settings) bool { return true }
func (f fakeScanner) Timeout(scanner.Settings) time.Duration {
	if f.timeout > 0 {
		return f.timeout
	}
	return time.Minute
}

func (f fakeScanner) Command(scanner.Env, scanner.Settings) scanner.Cmd {
	return scanner.Cmd{Path: f.id, OKExitCodes: f.ok}
}

func (f fakeScanner) Parse(scanner.Env) ([]finding.Finding, error) { return f.findings, f.parseErr }
func (f fakeScanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: f.id, Args: []string{"--version"}}
}

type fakeRunner struct {
	exit     map[string]int
	out      map[string]string
	sleep    map[string]time.Duration
	err      map[string]error
	inFlight atomic.Int32
	maxSeen  atomic.Int32
}

func (r *fakeRunner) Run(ctx context.Context, c scanner.Cmd, _ string) (int, []byte, error) {
	if len(c.Args) > 0 && c.Args[0] == "--version" {
		return 0, []byte(c.Path + " version v1.2.3\n"), nil
	}
	n := r.inFlight.Add(1)
	defer r.inFlight.Add(-1)
	for {
		m := r.maxSeen.Load()
		if n <= m || r.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	if d := r.sleep[c.Path]; d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return -1, nil, ctx.Err()
		}
	}
	return r.exit[c.Path], []byte(r.out[c.Path]), r.err[c.Path]
}

func TestRunCollectsAndMarksPartial(t *testing.T) {
	good := fakeScanner{id: "good", findings: []finding.Finding{{Tool: "good", RuleID: "r1", Category: finding.CategorySAST, Title: "t"}}}
	exit1OK := fakeScanner{id: "lenient", ok: []int{0, 1}, findings: []finding.Finding{{Tool: "lenient", RuleID: "r2", Category: finding.CategorySAST, Title: "u"}}}
	crash := fakeScanner{id: "crash"}
	badParse := fakeScanner{id: "badparse", parseErr: errors.New("boom")}
	slow := fakeScanner{id: "slow", timeout: 50 * time.Millisecond}
	missing := fakeScanner{id: "missing"}

	r := &fakeRunner{
		exit:  map[string]int{"lenient": 1, "crash": 2},
		out:   map[string]string{"crash": "fatal: token " + fixtureValue + " rejected"},
		sleep: map[string]time.Duration{"slow": time.Second},
		err:   map[string]error{"missing": errors.New("executable file not found")},
	}
	env := scanner.Env{TmpDir: t.TempDir()}
	res := Run(context.Background(), r, env, scanner.Settings{}, &detect.Result{},
		[]scanner.Scanner{good, exit1OK, crash, badParse, slow, missing}, Options{Parallelism: 2})

	byID := map[string]ToolRun{}
	for _, tr := range res.Tools {
		byID[tr.ID] = tr
	}
	want := map[string]string{
		"good": StatusOK, "lenient": StatusOK, "crash": StatusFailed,
		"badparse": StatusFailed, "slow": StatusTimeout, "missing": StatusFailed,
	}
	for id, st := range want {
		if byID[id].Status != st {
			t.Errorf("%s status %q want %q (%s)", id, byID[id].Status, st, byID[id].Error)
		}
	}
	if byID["good"].Version != "1.2.3" || byID["good"].Findings != 1 {
		t.Errorf("good run: %+v", byID["good"])
	}
	if strings.Contains(byID["crash"].LogExcerpt, fixtureValue) {
		t.Errorf("secret leaked into log excerpt: %q", byID["crash"].LogExcerpt)
	}
	if !res.Partial {
		t.Error("result must be partial")
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		if f.Fingerprint == "" {
			t.Error("findings must be normalized (fingerprint)")
		}
	}
	if r.maxSeen.Load() > 2 {
		t.Errorf("parallelism exceeded: %d", r.maxSeen.Load())
	}
}

func TestRunAllOK(t *testing.T) {
	res := Run(context.Background(), &fakeRunner{}, scanner.Env{TmpDir: t.TempDir()}, scanner.Settings{}, &detect.Result{},
		[]scanner.Scanner{fakeScanner{id: "a"}}, Options{})
	if res.Partial || res.Tools[0].Status != StatusOK {
		t.Fatalf("%+v", res)
	}
}

type ppScanner struct{ fakeScanner }

func (ppScanner) PostProcess(all []finding.Finding) []finding.Finding {
	return append(all, finding.Finding{Tool: "pp", RuleID: "added", Category: finding.CategorySAST, Title: "pp"})
}

func TestPostProcessorRuns(t *testing.T) {
	res := Run(context.Background(), &fakeRunner{}, scanner.Env{TmpDir: t.TempDir()}, scanner.Settings{}, &detect.Result{},
		[]scanner.Scanner{ppScanner{fakeScanner{id: "p"}}}, Options{})
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "added" {
		t.Fatalf("post processor not applied: %+v", res.Findings)
	}
}

func TestExecRunner(t *testing.T) {
	r := ExecRunner{BaseEnv: []string{"PATH=/usr/bin:/bin"}}
	code, out, err := r.Run(context.Background(), scanner.Cmd{Path: "sh", Args: []string{"-c", "echo hi; exit 3"}}, t.TempDir())
	if code != 3 || strings.TrimSpace(string(out)) != "hi" || !isExitError(err) {
		t.Fatalf("code=%d out=%q err=%v", code, out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _ = r.Run(ctx, scanner.Cmd{Path: "sh", Args: []string{"-c", "sleep 5 & sleep 5"}}, t.TempDir())
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout did not kill the process group")
	}
}

func TestHelpers(t *testing.T) {
	if parseVersion([]byte("Version: 0.75.0\n")) != "0.75.0" || parseVersion([]byte("opengrep 1.30.0")) != "1.30.0" || parseVersion([]byte("none")) != "" {
		t.Fatal("parseVersion")
	}
	long := strings.Repeat("x", 10000)
	if len(excerpt([]byte(long))) != 4096 {
		t.Fatal("excerpt length")
	}
	var lb limitedBuffer
	lb.max = 4
	_, _ = lb.Write([]byte("abcdef"))
	if string(lb.Bytes()) != "cdef" {
		t.Fatalf("limitedBuffer %q", lb.Bytes())
	}
	env := DefaultBaseEnv(scanner.Env{ToolHome: "/h", TmpDir: "/t"})
	joined := strings.Join(env, " ")
	if !strings.Contains(joined, "HOME=/t") || !strings.Contains(joined, "DO_NOT_TRACK=1") {
		t.Fatalf("env %v", env)
	}
}

func TestExcluded(t *testing.T) {
	pats := []string{"testdata", "*.min.js", "docs/examples", "./bin/"}
	cases := map[string]bool{
		"testdata/repos/x.php": true, "internal/testdata/a.go": true, "web/app.min.js": true,
		"docs/examples/r.html": true, "docs/examples": true, "bin/scanx": true,
		"docs/user/install.md": false, "internal/test.go": false, "": false, "mytestdata/x": false,
	}
	for p, want := range cases {
		if got := Excluded(p, pats); got != want {
			t.Errorf("Excluded(%q)=%v want %v", p, got, want)
		}
	}
	fs := FilterExcluded([]finding.Finding{{File: "testdata/a"}, {File: "src/a"}, {File: ""}}, pats)
	if len(fs) != 2 {
		t.Fatalf("filter %v", fs)
	}
	if got := FilterExcluded(fs, nil); len(got) != 2 {
		t.Fatal("no patterns must keep everything")
	}
}

func TestRunWritesProgress(t *testing.T) {
	var buf bytes.Buffer
	Run(context.Background(), &fakeRunner{}, scanner.Env{TmpDir: t.TempDir()}, scanner.Settings{}, &detect.Result{},
		[]scanner.Scanner{fakeScanner{id: "a"}}, Options{Progress: &buf})
	out := buf.String()
	for _, want := range []string{"1 scanners selected", "started", "ok in"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress missing %q:\n%s", want, out)
		}
	}
}
