package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
)

func sampleResult() *engine.Result {
	pkg := &finding.PackageRef{Name: "guzzlehttp/guzzle", Version: "7.4.0", FixedVersion: "7.4.5", Ecosystem: "packagist"}
	fs := []finding.Finding{
		{
			Tool: "opengrep", RuleID: "scanx.php.sqli", Category: finding.CategorySAST, Severity: finding.High, Title: "SQL injection <script>alert(1)</script>",
			File: "public/index.php", StartLine: 10, EndLine: 10, CWE: []string{"CWE-89"}, Snippet: `$q = "<b>" . $_GET['id'];`, References: []string{"https://owasp.org"},
		},
		{
			Tool: "trivy", RuleID: "CVE-2022-31090", Category: finding.CategorySCA, Severity: finding.Critical, Title: "CVE-2022-31090 in guzzle",
			CVE: []string{"CVE-2022-31090"}, Package: pkg, File: "composer.lock",
		},
		{
			Tool: "osv-scanner", RuleID: "GHSA-25mq-v84q-4j7r", Category: finding.CategorySCA, Severity: finding.High, Title: "GHSA in guzzle",
			CVE: []string{"GHSA-25mq-v84q-4j7r", "CVE-2022-31090"}, Package: pkg, File: "composer.lock",
		},
		{Tool: "trivy", RuleID: "DS-0026", Category: finding.CategoryIaC, Severity: finding.Low, Title: "No HEALTHCHECK", File: "Dockerfile"},
		{Tool: "x", RuleID: "nofile", Category: finding.CategoryLicense, Severity: finding.Info, Title: "no location"},
	}
	finding.Normalize(fs, finding.NormalizeOptions{StoreSnippets: true})
	return &engine.Result{
		Detection: &detect.Result{Ecosystems: []string{"composer"}, Lockfiles: []string{"composer.json"}},
		Tools:     []engine.ToolRun{{ID: "opengrep", Name: "Opengrep", Status: engine.StatusOK, Findings: 1}, {ID: "trivy-fs", Name: "Trivy", Status: engine.StatusFailed, Error: "exit code 2"}},
		Findings:  fs,
		Partial:   true,
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		s    Summary
		want int
	}{
		{Summary{}, 100}, {Summary{Critical: 1}, 75}, {Summary{High: 2, Medium: 1, Low: 1}, 77}, {Summary{Critical: 5}, 0}, {Summary{Low: 1}, 100},
	}
	for _, c := range cases {
		if got := Score(c.s); got != c.want {
			t.Errorf("Score(%+v)=%d want %d", c.s, got, c.want)
		}
	}
}

func TestPolicy(t *testing.T) {
	sum := Summary{Critical: 1, High: 3, Medium: 2}
	p, err := ParseFailOn("high")
	if err != nil {
		t.Fatal(err)
	}
	g := p.Evaluate(sum)
	if g.Result != "fail" || strings.Join(g.Reasons, ",") != "critical=1,high=3" {
		t.Fatalf("%+v", g)
	}
	none, _ := ParseFailOn("none")
	if none.Evaluate(sum).Result != "pass" || none.String() != "none" {
		t.Fatal("none must pass")
	}
	if _, err := ParseFailOn("urgent"); err == nil {
		t.Fatal("invalid --fail-on accepted")
	}
	th := Policy{Thresholds: map[finding.Severity]int{finding.Critical: 0, finding.High: 5}}
	g = th.Evaluate(sum)
	if g.Result != "fail" || len(g.Reasons) != 1 || g.Reasons[0] != "critical=1>0" || th.String() != "critical>0 OR high>5" {
		t.Fatalf("thresholds: %+v %q", g, th.String())
	}
	if th.Evaluate(Summary{High: 5}).Result != "pass" {
		t.Fatal("high=5 within limit must pass")
	}
}

func TestBuildMergesAndWarns(t *testing.T) {
	start := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	p, _ := ParseFailOn("critical")
	r := Build(sampleResult(), Target{Repo: "ininia/demo", Branch: "main"}, start, start.Add(90*time.Second), p)
	if r.Summary.Total != 4 || r.Summary.Critical != 1 || r.Summary.High != 1 {
		t.Fatalf("trivy+osv duplicate must merge: %+v", r.Summary)
	}
	if r.Gate.Result != "fail" || r.Score != 100-25-10-0 {
		t.Fatalf("gate %+v score %d", r.Gate, r.Score)
	}
	if !r.Partial || len(r.Warnings) != 2 {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if r.DurationSec != 90 || r.SchemaVersion != 1 {
		t.Fatalf("meta %+v", r)
	}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back["score"].(float64) != 65 {
		t.Fatalf("json score %v", back["score"])
	}
}

func TestSARIF(t *testing.T) {
	r := Build(sampleResult(), Target{}, time.Now(), time.Now(), Policy{})
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "scanX" {
		t.Fatalf("%+v", log)
	}
	res := log.Runs[0].Results
	if len(res) != 3 { // the issue without a file is excluded
		t.Fatalf("results %d", len(res))
	}
	ruleIDs := map[string]bool{}
	for _, rl := range log.Runs[0].Tool.Driver.Rules {
		ruleIDs[rl.ID] = true
		if rl.Properties["security-severity"] == "" {
			t.Errorf("rule %s missing security-severity", rl.ID)
		}
	}
	for _, x := range res {
		if !ruleIDs[x.RuleID] || x.PartialFingerprints["scanx/v1"] == "" || len(x.Locations) != 1 {
			t.Errorf("bad result %+v", x)
		}
	}
	if res[0].Level != "error" {
		t.Errorf("critical must be error, got %s", res[0].Level)
	}
	if !strings.Contains(res[0].Message.Text, "reported by osv-scanner, trivy") {
		t.Errorf("merged sources missing: %s", res[0].Message.Text)
	}
}

func TestHTMLEscapesUntrustedContent(t *testing.T) {
	r := Build(sampleResult(), Target{Repo: `evil"><script>x()</script>`}, time.Now(), time.Now(), Policy{})
	var buf bytes.Buffer
	if err := r.WriteHTML(&buf); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<script>x()</script>") || strings.Contains(html, "<b>\" .") {
		t.Fatal("untrusted content rendered unescaped")
	}
	for _, want := range []string{"SQL injection &lt;script&gt;", "Security score", "guzzlehttp/guzzle@7.4.0", "exit code 2", "<!doctype html>"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(html, "http://") && strings.Contains(html, "<script src") {
		t.Fatal("report must not load external scripts")
	}
}

func TestHasLockfile(t *testing.T) {
	if !hasLockfile([]string{"composer.lock"}) || !hasLockfile([]string{"a/go.sum"}) || hasLockfile([]string{"package.json"}) {
		t.Fatal("hasLockfile")
	}
}
