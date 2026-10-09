// Package extra adapts the additional analysers of the all-in-one image:
// DevSkim (Microsoft, multi-language security patterns incl. C#), zizmor
// (GitHub Actions workflow security), Checkov (infrastructure as code),
// Hadolint (Dockerfiles), ShellCheck (shell scripts), Bandit (Python) and
// Lizard (code complexity). All run offline inside the network-less scan
// container; none of them is given credentials or an online mode.
package extra

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/sarif"
)

func init() {
	scanner.Register(DevSkim{})
	scanner.Register(Zizmor{})
	scanner.Register(Checkov{})
	scanner.Register(Hadolint{})
	scanner.Register(ShellCheck{})
	scanner.Register(Bandit{})
	scanner.Register(Lizard{})
}

func readSARIF(env scanner.Env, file string, opt sarif.Options) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, file)) //nolint:gosec // our output dir
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	return sarif.Parse(data, opt)
}

// codeLanguages are languages DevSkim and Lizard analyse.
var codeLanguages = []string{
	"csharp", "javascript", "typescript", "java", "python", "go", "php", "ruby", "c", "cpp",
	"kotlin", "swift", "scala", "rust", "objectivec", "powershell",
}

func hasAny(d *detect.Result, langs ...string) bool {
	if d == nil {
		return true
	}
	for _, l := range langs {
		if d.HasLanguage(l) {
			return true
		}
	}
	return false
}

// ---------- DevSkim ----------

// DevSkim is Microsoft's security linter (pattern rules for many languages).
type DevSkim struct{}

// ID implements scanner.Scanner.
func (DevSkim) ID() string { return "devskim" }

// Name implements scanner.Scanner.
func (DevSkim) Name() string { return "DevSkim (security patterns, Microsoft)" }

// Tool implements scanner.Scanner.
func (DevSkim) Tool() string { return "devskim" }

// Category implements scanner.Scanner.
func (DevSkim) Category() finding.Category { return finding.CategorySAST }

// Applies implements scanner.Scanner.
func (DevSkim) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, codeLanguages...) }

// Timeout implements scanner.Scanner.
func (DevSkim) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// dotnetEnv: the image has no ICU (globalization-invariant mode) and .NET
// must never try telemetry; tools only get the variables passed here.
var dotnetEnv = []string{"DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1"}

// pythonEnv: the venv is read-only.
var pythonEnv = []string{"PYTHONDONTWRITEBYTECODE=1"}

// VersionCmd implements scanner.VersionReporter.
func (DevSkim) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "devskim", Args: []string{"--version"}, Env: dotnetEnv}
}

// Command implements scanner.Scanner.
func (DevSkim) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	var globs []string
	for _, ex := range scanner.AllExcludes(s) {
		globs = append(globs, "**/"+ex, "**/"+ex+"/**")
	}
	return scanner.Cmd{Path: "devskim", Args: []string{
		"analyze", "--source-code", env.SourceDir, "--output-file", filepath.Join(env.OutDir, "devskim.sarif"),
		"--file-format", "sarif", "--ignore-globs", strings.Join(globs, ","),
	}, OKExitCodes: []int{0, 1}, Env: dotnetEnv}
}

// devskimSeverity: DevSkim puts its own severity in the rule properties
// (critical/important/moderate/best-practice/manual-review).
func devskimSeverity(r sarif.Result, rule *sarif.Rule) finding.Severity {
	if rule != nil {
		if v, ok := rule.Properties["DevSkimSeverity"].(string); ok {
			switch strings.ToLower(v) {
			case "critical":
				return finding.High
			case "important":
				return finding.Medium
			case "moderate":
				return finding.Low
			default:
				return finding.Info
			}
		}
	}
	return sarif.DefaultSeverity(r, rule)
}

// Parse implements scanner.Scanner.
func (DevSkim) Parse(env scanner.Env) ([]finding.Finding, error) {
	return readSARIF(env, "devskim.sarif", sarif.Options{Tool: "devskim", Category: finding.CategorySAST, Severity: devskimSeverity})
}

// ---------- zizmor ----------

// Zizmor audits GitHub Actions workflows (injection, secret exposure,
// dangerous triggers, unpinned actions). Run with --offline: it never asks
// the GitHub API.
type Zizmor struct{}

// ID implements scanner.Scanner.
func (Zizmor) ID() string { return "zizmor" }

// Name implements scanner.Scanner.
func (Zizmor) Name() string { return "zizmor (GitHub Actions security)" }

// Tool implements scanner.Scanner.
func (Zizmor) Tool() string { return "zizmor" }

// Category implements scanner.Scanner.
func (Zizmor) Category() finding.Category { return finding.CategoryIaC }

// Applies implements scanner.Scanner: only repositories with workflows. The
// check runs at command time (detection does not record directories).
func (Zizmor) Applies(*detect.Result, scanner.Settings) bool { return true }

// Timeout implements scanner.Scanner.
func (Zizmor) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Zizmor) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "zizmor", Args: []string{"--version"}}
}

func hasWorkflows(root string) bool {
	st, err := os.Stat(filepath.Join(root, ".github", "workflows"))
	return err == nil && st.IsDir()
}

// Command implements scanner.Scanner. Without workflows it runs a no-op so
// the tool shows as "ok" with zero findings.
func (Zizmor) Command(env scanner.Env, _ scanner.Settings) scanner.Cmd {
	out := filepath.Join(env.OutDir, "zizmor.sarif")
	if !hasWorkflows(env.SourceDir) {
		return scanner.Cmd{Path: "true", StdoutFile: out}
	}
	return scanner.Cmd{
		Path:        "zizmor",
		Args:        []string{"--offline", "--no-progress", "--format", "sarif", "--no-exit-codes", "--cache-dir", filepath.Join(env.TmpDir, "zizmor"), env.SourceDir},
		StdoutFile:  out,
		OKExitCodes: []int{0},
	}
}

// zizmorSeverity: zizmor sets the SARIF level from its own severity
// (error = high, warning = medium, note = low).
func zizmorSeverity(r sarif.Result, rule *sarif.Rule) finding.Severity {
	switch strings.ToLower(r.Level) {
	case "error":
		return finding.High
	case "warning":
		return finding.Medium
	case "note":
		return finding.Low
	}
	return sarif.DefaultSeverity(r, rule)
}

// Parse implements scanner.Scanner.
func (Zizmor) Parse(env scanner.Env) ([]finding.Finding, error) {
	return readSARIF(env, "zizmor.sarif", sarif.Options{Tool: "zizmor", Category: finding.CategoryIaC, Severity: zizmorSeverity})
}

// ---------- Checkov ----------

// Checkov checks infrastructure as code. Online features (policy download,
// SCA, platform upload) stay off: no API key is ever given.
type Checkov struct{}

// ID implements scanner.Scanner.
func (Checkov) ID() string { return "checkov" }

// Name implements scanner.Scanner.
func (Checkov) Name() string { return "Checkov (infrastructure as code)" }

// Tool implements scanner.Scanner.
func (Checkov) Tool() string { return "checkov" }

// Category implements scanner.Scanner.
func (Checkov) Category() finding.Category { return finding.CategoryIaC }

// Applies implements scanner.Scanner.
func (Checkov) Applies(d *detect.Result, _ scanner.Settings) bool {
	return d == nil || len(d.IaC) > 0
}

// Timeout implements scanner.Scanner.
func (Checkov) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Checkov) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "checkov", Args: []string{"--version"}}
}

// checkovFrameworks: configuration formats only (secrets and SCA are
// covered by Gitleaks/Trivy/OSV and Checkov's SCA needs the network).
var checkovFrameworks = "terraform,cloudformation,kubernetes,helm,kustomize,dockerfile,arm,bicep,serverless," +
	"github_actions,gitlab_ci,azure_pipelines,bitbucket_pipelines,circleci_pipelines,ansible,openapi"

// Command implements scanner.Scanner.
func (Checkov) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	args := []string{
		"--directory", env.SourceDir, "--framework", checkovFrameworks, "--skip-download",
		"--quiet", "--compact", "--output", "sarif", "--output-file-path", filepath.Join(env.OutDir, "checkov"),
	}
	for _, ex := range scanner.AllExcludes(s) {
		args = append(args, "--skip-path", globToRegex(ex))
	}
	// Checkov's parallel runner deadlocks when a worker's result is large
	// (child blocks writing it while the parent waits for the child), so
	// it runs in one process.
	return scanner.Cmd{Path: "checkov", Args: args, OKExitCodes: []int{0, 1},
		Env: append([]string{
			"BC_SKIP_MAPPING=TRUE", "CHECKOV_ALLOW_KUSTOMIZE_FILE_EDITS=False", "LOG_LEVEL=ERROR",
			"CHECKOV_PARALLELIZATION_TYPE=none",
		}, pythonEnv...)}
}

// globToRegex turns an exclude pattern into the regular expression Checkov
// expects for --skip-path ("*.svg" is not a valid regex and made Checkov
// crash): "*" matches within a path segment, a pattern without "/" matches
// a whole segment anywhere.
func globToRegex(glob string) string {
	var b strings.Builder
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return "(^|/)" + b.String() + "(/|$)"
}

// checkovSeverity: open-source Checkov leaves severities empty; failed
// checks are configuration weaknesses → medium, unless the check says so.
func checkovSeverity(r sarif.Result, rule *sarif.Rule) finding.Severity {
	if rule != nil {
		if v, ok := rule.Properties["severity"].(string); ok {
			if sev, err := finding.ParseSeverity(v); err == nil {
				return sev
			}
		}
	}
	if _, ok := r.Properties["security-severity"]; ok {
		return sarif.DefaultSeverity(r, rule)
	}
	return finding.Medium
}

// Parse implements scanner.Scanner.
func (Checkov) Parse(env scanner.Env) ([]finding.Finding, error) {
	fs, err := readSARIF(env, filepath.Join("checkov", "results_sarif.sarif"), sarif.Options{
		Tool: "checkov", Category: finding.CategoryIaC, Severity: checkovSeverity,
	})
	if os.IsNotExist(err) {
		return nil, nil // nothing to check
	}
	return fs, err
}

// ---------- Hadolint ----------

// Hadolint lints Dockerfiles (best practice and security: root user,
// curl | sh, unpinned base images…).
type Hadolint struct{}

// ID implements scanner.Scanner.
func (Hadolint) ID() string { return "hadolint" }

// Name implements scanner.Scanner.
func (Hadolint) Name() string { return "Hadolint (Dockerfile)" }

// Tool implements scanner.Scanner.
func (Hadolint) Tool() string { return "hadolint" }

// Category implements scanner.Scanner.
func (Hadolint) Category() finding.Category { return finding.CategoryIaC }

// Applies implements scanner.Scanner.
func (Hadolint) Applies(d *detect.Result, _ scanner.Settings) bool {
	if d == nil {
		return true
	}
	for _, k := range d.IaC {
		if k == "dockerfile" {
			return true
		}
	}
	return false
}

// Timeout implements scanner.Scanner.
func (Hadolint) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Hadolint) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "hadolint", Args: []string{"--version"}}
}

func isDockerfile(_, name string) bool {
	l := strings.ToLower(name)
	return l == "dockerfile" || strings.HasPrefix(l, "dockerfile.") || strings.HasSuffix(l, ".dockerfile") ||
		strings.HasSuffix(l, ".containerfile") || l == "containerfile"
}

// Command implements scanner.Scanner.
func (Hadolint) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	out := filepath.Join(env.OutDir, "hadolint.sarif")
	files := scanner.FindFiles(env.SourceDir, scanner.AllExcludes(s), 500, isDockerfile)
	if len(files) == 0 {
		return scanner.Cmd{Path: "true", StdoutFile: out}
	}
	return scanner.Cmd{Path: "hadolint", Args: append([]string{"--no-fail", "--format", "sarif"}, files...), StdoutFile: out}
}

// hadolintSeverity: error → medium, warning → low, info/style → info.
func hadolintSeverity(r sarif.Result, _ *sarif.Rule) finding.Severity {
	return sarif.FromLevel(r.Level)
}

// Parse implements scanner.Scanner.
func (Hadolint) Parse(env scanner.Env) ([]finding.Finding, error) {
	return readSARIF(env, "hadolint.sarif", sarif.Options{Tool: "hadolint", Category: finding.CategoryIaC, Severity: hadolintSeverity})
}

// ---------- Bandit ----------

// Bandit is the PyCQA security linter for Python.
type Bandit struct{}

// ID implements scanner.Scanner.
func (Bandit) ID() string { return "bandit" }

// Name implements scanner.Scanner.
func (Bandit) Name() string { return "Bandit (Python security)" }

// Tool implements scanner.Scanner.
func (Bandit) Tool() string { return "bandit" }

// Category implements scanner.Scanner.
func (Bandit) Category() finding.Category { return finding.CategorySAST }

// Applies implements scanner.Scanner.
func (Bandit) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, "python") }

// Timeout implements scanner.Scanner.
func (Bandit) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Bandit) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Env: pythonEnv, Path: "bandit", Args: []string{"--version"}}
}

// Command implements scanner.Scanner.
func (Bandit) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	var ex []string
	for _, e := range scanner.AllExcludes(s) {
		ex = append(ex, "*/"+e, "*/"+e+"/*")
	}
	return scanner.Cmd{Env: pythonEnv, Path: "bandit", Args: []string{
		"-r", env.SourceDir, "-f", "sarif", "-o", filepath.Join(env.OutDir, "bandit.sarif"), "-q", "--exit-zero",
		"-x", strings.Join(ex, ","),
	}}
}

// banditSeverity reads Bandit's issue_severity (LOW/MEDIUM/HIGH).
func banditSeverity(r sarif.Result, rule *sarif.Rule) finding.Severity {
	if v, ok := r.Properties["issue_severity"].(string); ok {
		switch strings.ToUpper(v) {
		case "HIGH":
			return finding.High
		case "MEDIUM":
			return finding.Medium
		case "LOW":
			return finding.Low
		}
	}
	return sarif.DefaultSeverity(r, rule)
}

// Parse implements scanner.Scanner.
func (Bandit) Parse(env scanner.Env) ([]finding.Finding, error) {
	return readSARIF(env, "bandit.sarif", sarif.Options{Tool: "bandit", Category: finding.CategorySAST, Severity: banditSeverity})
}
