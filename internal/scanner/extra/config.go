package extra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/sarif"
)

// ---------- actionlint ----------

// Actionlint checks GitHub Actions workflows for mistakes (invalid syntax,
// wrong expressions and action inputs, shell bugs via ShellCheck). zizmor
// covers workflow security; actionlint covers correctness.
type Actionlint struct{}

// ID implements scanner.Scanner.
func (Actionlint) ID() string { return "actionlint" }

// Name implements scanner.Scanner.
func (Actionlint) Name() string { return "actionlint (GitHub Actions correctness)" }

// Tool implements scanner.Scanner.
func (Actionlint) Tool() string { return "actionlint" }

// Category implements scanner.Scanner.
func (Actionlint) Category() finding.Category { return finding.CategoryQuality }

// Applies implements scanner.Scanner: workflows are looked for at command
// time, like zizmor.
func (Actionlint) Applies(*detect.Result, scanner.Settings) bool { return true }

// Timeout implements scanner.Scanner.
func (Actionlint) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Actionlint) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "actionlint", Args: []string{"-version"}}
}

func workflowFiles(root string) []string {
	var out []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", pat))
		for _, f := range m {
			if st, err := os.Lstat(f); err == nil && st.Mode().IsRegular() {
				rel, _ := filepath.Rel(root, f)
				out = append(out, filepath.ToSlash(rel))
			}
		}
	}
	return out
}

// Command implements scanner.Scanner.
func (Actionlint) Command(env scanner.Env, _ scanner.Settings) scanner.Cmd {
	out := filepath.Join(env.OutDir, "actionlint.json")
	files := workflowFiles(env.SourceDir)
	if len(files) == 0 {
		return scanner.Cmd{Path: "true", StdoutFile: out}
	}
	return scanner.Cmd{
		Path: "actionlint", Args: append([]string{"-format", "{{json .}}", "-no-color"}, files...),
		StdoutFile: out, OKExitCodes: []int{0, 1}, Dir: env.SourceDir,
	}
}

// Parse implements scanner.Scanner.
func (Actionlint) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, "actionlint.json"))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var errs []struct {
		Message  string `json:"message"`
		Filepath string `json:"filepath"`
		Line     int    `json:"line"`
		Kind     string `json:"kind"`
	}
	if err := json.Unmarshal(data, &errs); err != nil {
		return nil, fmt.Errorf("actionlint json: %w", err)
	}
	out := make([]finding.Finding, 0, len(errs))
	for _, e := range errs {
		sev := finding.Low
		if e.Kind == "syntax-check" || e.Kind == "expression" || e.Kind == "action" || e.Kind == "job-needs" {
			sev = finding.Medium
		}
		out = append(out, finding.Finding{
			Tool: "actionlint", RuleID: "actionlint." + e.Kind, Category: finding.CategoryQuality, Severity: sev,
			Title: firstSentence(e.Message), Description: e.Message,
			File: e.Filepath, StartLine: e.Line, EndLine: e.Line,
			References: []string{"https://github.com/rhysd/actionlint/blob/main/docs/checks.md"},
		})
	}
	return out, nil
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 && i < 160 {
		return s[:i]
	}
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

// ---------- kube-linter ----------

// KubeLinter checks Kubernetes manifests and Helm charts (privileged
// containers, root users, missing limits...). Files that are not
// Kubernetes objects are ignored by the tool.
type KubeLinter struct{}

// ID implements scanner.Scanner.
func (KubeLinter) ID() string { return "kube-linter" }

// Name implements scanner.Scanner.
func (KubeLinter) Name() string { return "kube-linter (Kubernetes)" }

// Tool implements scanner.Scanner.
func (KubeLinter) Tool() string { return "kube-linter" }

// Category implements scanner.Scanner.
func (KubeLinter) Category() finding.Category { return finding.CategoryIaC }

// Applies implements scanner.Scanner: only repositories with YAML or Helm
// charts can contain manifests.
func (KubeLinter) Applies(d *detect.Result, _ scanner.Settings) bool {
	return d == nil || d.HasIaC("yaml") || d.HasIaC("helm") || d.HasIaC("kubernetes")
}

// Timeout implements scanner.Scanner.
func (KubeLinter) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (KubeLinter) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "kube-linter", Args: []string{"version"}}
}

// Command implements scanner.Scanner.
func (KubeLinter) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	args := []string{"lint", "--format", "sarif"}
	for _, ex := range scanner.AllExcludes(s) {
		args = append(args, "--ignore-paths", "**/"+ex, "--ignore-paths", "**/"+ex+"/**")
	}
	return scanner.Cmd{
		Path: "kube-linter", Args: append(args, "."), StdoutFile: filepath.Join(env.OutDir, "kube-linter.sarif"),
		OKExitCodes: []int{0, 1}, Dir: env.SourceDir,
	}
}

// kubeHigh are checks that give a container host-level access; kubeLow
// are reliability/hygiene checks. Everything else is medium.
var (
	kubeHigh = map[string]bool{
		"privileged-container": true, "privilege-escalation-container": true, "host-network": true, "host-pid": true,
		"host-ipc": true, "docker-sock": true, "sensitive-host-mounts": true, "writable-host-mount": true,
		"unsafe-sysctls": true, "cluster-admin-role-binding": true, "env-var-secret": true, "access-to-secrets": true,
		"access-to-create-pods": true, "wildcard-in-rules": true, "unsafe-proc-mount": true,
	}
	kubeLow = map[string]bool{
		"unset-cpu-requirements": true, "unset-memory-requirements": true, "latest-tag": true,
		"no-liveness-probe": true, "no-readiness-probe": true, "minimum-replicas": true, "no-anti-affinity": true,
		"no-rolling-update-strategy": true, "required-annotation-email": true, "required-label-owner": true,
		"dangling-service": true, "non-isolated-pod": true, "default-service-account": true,
		"mismatching-selector": true, "pdb-max-unavailable": true, "pdb-min-available": true,
	}
)

func kubeSeverity(r sarif.Result, _ *sarif.Rule) finding.Severity {
	switch {
	case kubeHigh[r.RuleID]:
		return finding.High
	case kubeLow[r.RuleID]:
		return finding.Low
	}
	return finding.Medium
}

// Parse implements scanner.Scanner.
func (KubeLinter) Parse(env scanner.Env) ([]finding.Finding, error) {
	found, err := readSARIF(env, "kube-linter.sarif", sarif.Options{
		Tool: "kube-linter", Category: finding.CategoryIaC, Severity: kubeSeverity, TitleFromMessage: true,
	})
	if err != nil {
		return nil, err
	}
	for i := range found {
		found[i].RuleID = "kube-linter." + found[i].RuleID
	}
	return found, nil
}

// ---------- Spectral (OpenAPI) ----------

// Spectral (Stoplight, Apache-2.0) lints OpenAPI/Swagger documents with
// the OWASP API Security Top 10 ruleset (bundled; nothing is fetched).
type Spectral struct{}

// ID implements scanner.Scanner.
func (Spectral) ID() string { return "spectral" }

// Name implements scanner.Scanner.
func (Spectral) Name() string { return "Spectral (OpenAPI, OWASP API Top 10)" }

// Tool implements scanner.Scanner.
func (Spectral) Tool() string { return "spectral" }

// Category implements scanner.Scanner.
func (Spectral) Category() finding.Category { return finding.CategoryIaC }

// Applies implements scanner.Scanner.
func (Spectral) Applies(d *detect.Result, _ scanner.Settings) bool {
	return d == nil || d.HasIaC("openapi") || d.HasIaC("yaml")
}

// Timeout implements scanner.Scanner.
func (Spectral) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Spectral) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "spectral", Args: []string{"--version"}, Env: []string{"NODE_NO_WARNINGS=1"}}
}

// isAPISpec reads the start of a YAML/JSON file and looks for the
// top-level "openapi"/"swagger" key.
func isAPISpec(path string) bool {
	f, err := os.Open(path) //nolint:gosec // file inside the scanned tree
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || st.Size() > 5<<20 {
		return false
	}
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	for _, line := range strings.Split(string(head[:n]), "\n") {
		l := strings.TrimSpace(line)
		for _, key := range []string{"openapi", "swagger"} {
			if strings.HasPrefix(line, key+":") || strings.HasPrefix(l, `"`+key+`"`) || strings.HasPrefix(l, `{"`+key+`"`) {
				return true
			}
		}
	}
	return false
}

func apiSpecFiles(root string, excludes []string) []string {
	return scanner.FindFiles(root, excludes, 100, func(_, name string) bool {
		l := strings.ToLower(name)
		if !strings.HasSuffix(l, ".yaml") && !strings.HasSuffix(l, ".yml") && !strings.HasSuffix(l, ".json") {
			return false
		}
		return !strings.HasSuffix(l, "package.json") && !strings.HasSuffix(l, "lock.json")
	})
}

// Command implements scanner.Scanner.
func (Spectral) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	out := filepath.Join(env.OutDir, "spectral.json")
	var specs []string
	for _, f := range apiSpecFiles(env.SourceDir, scanner.AllExcludes(s)) {
		if isAPISpec(f) {
			specs = append(specs, f)
		}
	}
	if len(specs) == 0 {
		return scanner.Cmd{Path: "true", StdoutFile: out}
	}
	args := []string{
		"lint", "--ruleset", filepath.Join(env.ConfigDir, "spectral", "ruleset.mjs"),
		"--format", "json", "--output", out, "--quiet", "--fail-severity", "error",
	}
	return scanner.Cmd{Path: "spectral", Args: append(args, specs...), OKExitCodes: []int{0, 1}, Env: []string{"NODE_NO_WARNINGS=1"}}
}

// spectralSeverity: the OWASP ruleset marks schema-hygiene rules (integer
// formats, limits) as errors and missing authentication as a warning, so
// scanX decides: authentication/authorisation (API2), mass assignment
// (API3) and plain-HTTP servers are medium; the rest low, hints info.
func spectralSeverity(code string, sev int) finding.Severity {
	switch {
	case sev >= 2:
		return finding.Info
	case strings.Contains(code, ":api2:"), strings.Contains(code, ":api3:"), strings.HasSuffix(code, "no-server-http"):
		return finding.Medium
	}
	return finding.Low
}

// Parse implements scanner.Scanner. Spectral severities: 0 error,
// 1 warning, 2 info, 3 hint.
func (Spectral) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, "spectral.json"))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var res []struct {
		Code     string `json:"code"`
		Message  string `json:"message"`
		Severity int    `json:"severity"`
		Source   string `json:"source"`
		Range    struct {
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
		} `json:"range"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("spectral json: %w", err)
	}
	var out []finding.Finding
	for _, r := range res {
		if r.Code == "invalid-ref" { // remote $ref: never fetched (offline)
			continue
		}
		out = append(out, finding.Finding{
			Tool: "spectral", RuleID: r.Code, Category: finding.CategoryIaC, Severity: spectralSeverity(r.Code, r.Severity),
			Title: r.Message, Description: r.Message,
			File: r.Source, StartLine: r.Range.Start.Line + 1, EndLine: r.Range.End.Line + 1,
			References: []string{"https://github.com/stoplightio/spectral-owasp-ruleset"},
		})
	}
	return out, nil
}
