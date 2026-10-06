// Package trivy adapts Trivy filesystem scans: dependency vulnerabilities,
// IaC misconfigurations, secrets and licenses.
package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

const outFile = "trivy.json"

// Scanner is the Trivy adapter.
type Scanner struct{}

func init() { scanner.Register(Scanner{}) }

// ID implements scanner.Scanner.
func (Scanner) ID() string { return "trivy-fs" }

// Name implements scanner.Scanner.
func (Scanner) Name() string { return "Trivy (dependencies, IaC, secrets, licenses)" }

// Tool implements scanner.Scanner.
func (Scanner) Tool() string { return "trivy" }

// Category implements scanner.Scanner.
func (Scanner) Category() finding.Category { return finding.CategorySCA }

// Applies implements scanner.Scanner: Trivy is useful for every repository
// (secrets and misconfigurations need no manifest).
func (Scanner) Applies(*detect.Result, scanner.Settings) bool { return true }

// Timeout implements scanner.Scanner.
func (Scanner) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Scanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "trivy", Args: []string{"--version"}}
}

// Command implements scanner.Scanner. Everything that could reach the
// network (DB/check updates, version check, telemetry, Maven) is disabled.
func (Scanner) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	args := []string{
		"fs", env.SourceDir,
		"--scanners", "vuln,misconfig,secret,license",
		"--cache-dir", filepath.Join(env.DBDir, "trivy"),
		"--cache-backend", "memory",
		"--skip-db-update", "--skip-java-db-update", "--skip-check-update",
		"--offline-scan", "--skip-version-check", "--disable-telemetry",
		"--format", "json", "--output", filepath.Join(env.OutDir, outFile),
		"--exit-code", "0", "--quiet",
	}
	for _, ex := range append(append([]string{}, scanner.DefaultExcludes...), s.Exclude...) {
		if strings.ContainsAny(ex, "*?") {
			args = append(args, "--skip-files", ex)
		} else {
			args = append(args, "--skip-dirs", ex)
		}
	}
	return scanner.Cmd{Path: "trivy", Args: args}
}

type report struct {
	Results []struct {
		Target            string    `json:"Target"`
		Class             string    `json:"Class"`
		Type              string    `json:"Type"`
		Vulnerabilities   []vuln    `json:"Vulnerabilities"`
		Misconfigurations []misconf `json:"Misconfigurations"`
		Secrets           []secret  `json:"Secrets"`
		Licenses          []license `json:"Licenses"`
	} `json:"Results"`
}

type vuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgIdentifier   struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	InstalledVersion string                     `json:"InstalledVersion"`
	FixedVersion     string                     `json:"FixedVersion"`
	PrimaryURL       string                     `json:"PrimaryURL"`
	Title            string                     `json:"Title"`
	Description      string                     `json:"Description"`
	Severity         string                     `json:"Severity"`
	CweIDs           []string                   `json:"CweIDs"`
	CVSS             map[string]json.RawMessage `json:"CVSS"`
	References       []string                   `json:"References"`
}

type misconf struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	Status        string   `json:"Status"`
	CauseMetadata struct {
		StartLine int `json:"StartLine"`
		EndLine   int `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

type license struct {
	Severity   string  `json:"Severity"`
	Category   string  `json:"Category"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath"`
	Name       string  `json:"Name"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link"`
}

// Parse implements scanner.Scanner.
func (Scanner) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, outFile))
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func parse(data []byte) ([]finding.Finding, error) {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("trivy json: %w", err)
	}
	var out []finding.Finding
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, vulnFinding(res.Target, res.Type, v))
		}
		for _, m := range res.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			sev, _ := finding.FromVendor(m.Severity)
			title := m.Title
			if m.Message != "" {
				title = m.Title + ": " + m.Message
			}
			out = append(out, finding.Finding{
				Tool: "trivy", RuleID: m.ID, Category: finding.CategoryIaC, Severity: sev,
				Title: title, Description: m.Description, Remediation: m.Resolution,
				File: res.Target, StartLine: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine,
				References: refs(m.PrimaryURL, m.References),
			})
		}
		for _, s := range res.Secrets {
			f := finding.Finding{
				Tool: "trivy", RuleID: s.RuleID, Category: finding.CategorySecret,
				Severity: finding.SecretSeverity(s.RuleID, false),
				Title:    s.Title, File: res.Target, StartLine: s.StartLine, EndLine: s.EndLine,
				CWE: []string{"CWE-798"},
			}
			// Trivy already redacts Match; use it as the fingerprint input so
			// gitleaks and trivy agree on the identity of the same secret.
			f.SetMatchLines(finding.MaskText(s.Match))
			out = append(out, f)
		}
		for _, l := range res.Licenses {
			out = append(out, licenseFinding(res.Target, l))
		}
	}
	return out, nil
}

func vulnFinding(target, ecosystem string, v vuln) finding.Finding {
	sev, ok := finding.FromVendor(v.Severity)
	if score := bestCVSS(v.CVSS); score > 0 && (!ok || v.Severity == "UNKNOWN") {
		sev = finding.FromCVSS(score)
	}
	title := v.VulnerabilityID + " in " + v.PkgName + " " + v.InstalledVersion
	if v.Title != "" {
		title += ": " + v.Title
	}
	rem := ""
	if v.FixedVersion != "" {
		rem = "Upgrade " + v.PkgName + " to " + v.FixedVersion + " or later."
	}
	return finding.Finding{
		Tool: "trivy", RuleID: v.VulnerabilityID, Category: finding.CategorySCA, Severity: sev,
		Title: title, Description: v.Description, Remediation: rem,
		CVE: []string{v.VulnerabilityID}, CWE: finding.NormalizeCWEs(v.CweIDs...),
		Package: &finding.PackageRef{
			Name: v.PkgName, Version: v.InstalledVersion, FixedVersion: v.FixedVersion,
			Ecosystem: ecosystem, PURL: v.PkgIdentifier.PURL,
		},
		File: target, References: refs(v.PrimaryURL, v.References),
	}
}

// licenseFinding reports dependency licenses. Licensing is a compliance
// signal, not a vulnerability, so severities are capped at medium.
func licenseFinding(target string, l license) finding.Finding {
	sev, _ := finding.FromVendor(l.Severity)
	if sev > finding.Medium {
		sev = finding.Medium
	}
	file := target
	if l.FilePath != "" {
		file = l.FilePath
	}
	name := l.PkgName
	if name == "" {
		name = file
	}
	return finding.Finding{
		Tool: "trivy", RuleID: "license:" + l.Name, Category: finding.CategoryLicense, Severity: sev,
		Title:       fmt.Sprintf("%s license (%s) in %s", l.Name, strings.ToLower(l.Category), name),
		Description: "Review whether this license is compatible with how the software is distributed.",
		File:        file, References: refs(l.Link, nil),
	}
}

// bestCVSS returns the highest V3/V4 base score across sources.
func bestCVSS(m map[string]json.RawMessage) float64 {
	var best float64
	for _, raw := range m {
		var c struct {
			V3Score float64 `json:"V3Score"`
			V40     float64 `json:"V40Score"`
		}
		if json.Unmarshal(raw, &c) == nil {
			best = max(best, c.V3Score, c.V40)
		}
	}
	return best
}

func refs(primary string, rest []string) []string {
	var out []string
	if primary != "" {
		out = append(out, primary)
	}
	for _, r := range rest {
		if r != primary && len(out) < 10 {
			out = append(out, r)
		}
	}
	return out
}
