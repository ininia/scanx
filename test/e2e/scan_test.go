//go:build e2e

// Package e2e verifies a real scan report against the fixture's expected
// minimum findings. The report is produced beforehand by running the scanner
// image (see scripts/e2e-scan.sh), and its directory is passed in
// SCANX_E2E_OUT.
package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/report"
)

type expected struct {
	MinTotal int    `json:"min_total"`
	Gate     string `json:"gate_with_fail_on_high"`
	Issues   []struct {
		Tool        string `json:"tool"`
		Rule        string `json:"rule"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		MinSeverity string `json:"min_severity"`
		CWE         string `json:"cwe"`
	} `json:"issues"`
	Secrets []string `json:"secrets_never_in_report"`
}

func TestPHPVulnFixture(t *testing.T) {
	out := os.Getenv("SCANX_E2E_OUT")
	if out == "" {
		t.Skip("SCANX_E2E_OUT not set; run scripts/e2e-scan.sh")
	}
	var exp expected
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "expected", "php-vuln.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "scanx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}

	for _, tool := range rep.Tools {
		if tool.Status != "ok" {
			t.Errorf("scanner %s %s: %s", tool.ID, tool.Status, tool.Error)
		}
	}
	if rep.Summary.Total < exp.MinTotal {
		t.Errorf("total issues %d < %d", rep.Summary.Total, exp.MinTotal)
	}
	if rep.Gate.Result != exp.Gate {
		t.Errorf("gate %s want %s", rep.Gate.Result, exp.Gate)
	}

	for _, e := range exp.Issues {
		minSev, _ := finding.ParseSeverity(e.MinSeverity)
		found := false
		for _, is := range rep.Issues {
			for _, f := range is.Findings {
				if f.Tool != e.Tool || !strings.Contains(f.RuleID, e.Rule) || f.File != e.File {
					continue
				}
				if e.Line > 0 && f.StartLine != e.Line {
					continue
				}
				if is.Severity < minSev {
					t.Errorf("%s/%s severity %s < %s", e.Tool, e.Rule, is.Severity, minSev)
				}
				if e.CWE != "" && !contains(is.CWE, e.CWE) {
					t.Errorf("%s/%s missing %s (got %v)", e.Tool, e.Rule, e.CWE, is.CWE)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("expected finding not reported: %s %s %s:%d", e.Tool, e.Rule, e.File, e.Line)
		}
	}

	// No secret may appear in any output file.
	for _, name := range []string{"scanx.json", "scanx.sarif", "scanx.html"} {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		for _, s := range exp.Secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("plaintext secret found in %s", name)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); err != nil {
		t.Errorf("SBOM missing: %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
