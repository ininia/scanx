package extra

import (
	"errors"
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/sarif"
)

// Language-specific analysers. Each one runs only when files of its
// language were detected (Applies), so e.g. gosec never touches a .NET
// repository and Psalm never runs without PHP files.

// ---------- gosec (Go) ----------

// Gosec is the Go security checker (securego, Apache-2.0). Dependencies are
// not downloaded (the scan has no network): the AST rules run on every
// package, SSA-based rules only where types resolve.
type Gosec struct{}

// ID implements scanner.Scanner.
func (Gosec) ID() string { return "gosec" }

// Name implements scanner.Scanner.
func (Gosec) Name() string { return "gosec (Go security)" }

// Tool implements scanner.Scanner.
func (Gosec) Tool() string { return "gosec" }

// Category implements scanner.Scanner.
func (Gosec) Category() finding.Category { return finding.CategorySAST }

// Applies implements scanner.Scanner.
func (Gosec) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, "go") }

// Timeout implements scanner.Scanner.
func (Gosec) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Gosec) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "gosec", Args: []string{"-version"}}
}

// goEnv keeps the Go toolchain offline and inside the scratch directory.
func goEnv(env scanner.Env) []string {
	return []string{
		"GOPATH=" + filepath.Join(env.TmpDir, "gopath"), "GOCACHE=" + filepath.Join(env.TmpDir, "gocache"),
		"GOFLAGS=-mod=mod", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off",
		"GOWORK=off", "GOENV=off", "CGO_ENABLED=0",
	}
}

// gosecModules lists the module directories (repository-relative, "." for
// the root) in the order scanx-gosec numbers its reports.
const gosecModules = "gosec-modules.txt"

// goModuleDirs finds the Go modules of the repository; testdata modules
// are fixtures and never built.
func goModuleDirs(root string, excludes []string) []string {
	files := scanner.FindFiles(root, append(append([]string{}, excludes...), "testdata"), 50, func(_, name string) bool {
		return name == "go.mod"
	})
	out := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(root, filepath.Dir(f))
		if err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
	}
	return out
}

// Command implements scanner.Scanner. gosec only loads packages from
// inside a module, so the scanx-gosec wrapper runs it once per go.mod.
// G101 (hardcoded credentials) is left to Gitleaks: gosec matches variable
// names and flags translation keys such as "password".
func (Gosec) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	mods := goModuleDirs(env.SourceDir, scanner.AllExcludes(s))
	if len(mods) == 0 {
		return scanner.Cmd{Path: "true"}
	}
	if err := os.WriteFile(filepath.Join(env.OutDir, gosecModules), []byte(strings.Join(mods, "\n")+"\n"), 0o600); err != nil {
		return scanner.Cmd{Path: "false"}
	}
	var dirs []string
	for _, ex := range scanner.AllExcludes(s) {
		if !strings.ContainsAny(ex, "*?[/, ") {
			dirs = append(dirs, ex)
		}
	}
	args := []string{env.OutDir}
	for _, m := range mods {
		args = append(args, filepath.Join(env.SourceDir, filepath.FromSlash(m)))
	}
	return scanner.Cmd{
		Path: "scanx-gosec", Args: args,
		Env: append(goEnv(env), "SCANX_GOSEC_EXCLUDE_DIRS="+strings.Join(dirs, ",")),
	}
}

// gosecSeverity reads gosec's own severity (rule tag HIGH/MEDIUM/LOW) and
// lowers it one step when gosec itself has low confidence ("precision").
func gosecSeverity(r sarif.Result, rule *sarif.Rule) finding.Severity {
	if rule == nil {
		return sarif.DefaultSeverity(r, rule)
	}
	sev := finding.Low
	if tags, ok := rule.Properties["tags"].([]any); ok {
		for _, t := range tags {
			switch t {
			case "HIGH":
				sev = finding.High
			case "MEDIUM":
				sev = finding.Medium
			}
		}
	}
	if p, _ := rule.Properties["precision"].(string); p == "low" && sev > finding.Low {
		sev--
	}
	return sev
}

// Parse implements scanner.Scanner. Each module's report has paths
// relative to that module; they are prefixed with the module directory.
func (Gosec) Parse(env scanner.Env) ([]finding.Finding, error) {
	list, err := os.ReadFile(filepath.Join(env.OutDir, gosecModules))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // no Go module
	} else if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for i, mod := range strings.Fields(string(list)) {
		found, err := readSARIF(env, fmt.Sprintf("gosec-%d.sarif", i+1), sarif.Options{
			Tool: "gosec", Category: finding.CategorySAST, Severity: gosecSeverity,
		})
		if errors.Is(err, fs.ErrNotExist) {
			continue // nothing analysable in this module
		} else if err != nil {
			return nil, err
		}
		for j := range found {
			if f := found[j].File; f != "" && !filepath.IsAbs(f) && mod != "." {
				found[j].File = mod + "/" + f
			}
		}
		out = append(out, found...)
	}
	return out, nil
}

// ---------- Ruff (Python) ----------

// Ruff is a fast Python linter (Astral, MIT). It runs with scanX's own rule
// selection (--isolated ignores repository config): syntax errors and
// pyflakes (undefined names, unused code) plus bugbear (likely bugs).
// Security rules stay with Bandit.
type Ruff struct{}

// ID implements scanner.Scanner.
func (Ruff) ID() string { return "ruff" }

// Name implements scanner.Scanner.
func (Ruff) Name() string { return "Ruff (Python code quality)" }

// Tool implements scanner.Scanner.
func (Ruff) Tool() string { return "ruff" }

// Category implements scanner.Scanner.
func (Ruff) Category() finding.Category { return finding.CategoryQuality }

// Applies implements scanner.Scanner.
func (Ruff) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, "python") }

// Timeout implements scanner.Scanner.
func (Ruff) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Ruff) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "ruff", Args: []string{"--version"}}
}

// Command implements scanner.Scanner.
func (Ruff) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	return scanner.Cmd{Path: "ruff", Args: []string{
		"check", "--isolated", "--no-cache", "--exit-zero", "--quiet",
		"--select", "E9,F,B", "--extend-exclude", strings.Join(scanner.AllExcludes(s), ","),
		"--output-format", "sarif", "--output-file", filepath.Join(env.OutDir, "ruff.sarif"), env.SourceDir,
	}}
}

// ruffSeverity: syntax errors and undefined names are real bugs (medium);
// everything else is low. Quality findings never count towards the grade.
func ruffSeverity(r sarif.Result, _ *sarif.Rule) finding.Severity {
	id := r.RuleID
	if strings.HasPrefix(id, "E9") || strings.HasPrefix(id, "F82") || strings.HasPrefix(id, "F63") || strings.HasPrefix(id, "F7") {
		return finding.Medium
	}
	return finding.Low
}

// Parse implements scanner.Scanner.
func (Ruff) Parse(env scanner.Env) ([]finding.Finding, error) {
	return readSARIF(env, "ruff.sarif", sarif.Options{
		Tool: "ruff", Category: finding.CategoryQuality, Severity: ruffSeverity, TitleFromMessage: true,
	})
}

// ---------- Psalm (PHP) ----------

// Psalm (MIT) runs in taint-analysis mode: it follows user input
// ($_GET, $_POST, request objects...) to dangerous sinks (SQL, shell,
// include, echo, unserialize...). Dependencies are not installed; Psalm's
// built-in stubs cover PHP itself, PDO and mysqli.
type Psalm struct{}

// ID implements scanner.Scanner.
func (Psalm) ID() string { return "psalm" }

// Name implements scanner.Scanner.
func (Psalm) Name() string { return "Psalm (PHP taint analysis)" }

// Tool implements scanner.Scanner.
func (Psalm) Tool() string { return "psalm" }

// Category implements scanner.Scanner.
func (Psalm) Category() finding.Category { return finding.CategorySAST }

// Applies implements scanner.Scanner.
func (Psalm) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, "php") }

// Timeout implements scanner.Scanner.
func (Psalm) Timeout(scanner.Settings) time.Duration { return 20 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Psalm) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "psalm", Args: []string{"--version"}}
}

// psalmRoot is an empty working root: Psalm refuses to run in a directory
// with composer.json but no vendor/ (we never install dependencies), so
// the project is referenced from the config by absolute path instead.
func psalmRoot(env scanner.Env) string { return filepath.Join(env.TmpDir, "psalm-root") }

// excludedDirs lists the top-most existing directories under root that
// match the exclude patterns (Psalm only ignores paths that exist).
func excludedDirs(root string, patterns []string, limit int) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == root || len(out) >= limit {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr == nil && scanner.Excluded(rel, patterns) {
			out = append(out, p)
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

func psalmConfig(env scanner.Env, s scanner.Settings) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n")
	fmt.Fprintf(&b, `<psalm errorLevel="8" resolveFromConfigFile="false" findUnusedCode="false" findUnusedBaselineEntry="false" cacheDirectory="%s">`+"\n",
		html.EscapeString(filepath.Join(env.TmpDir, "psalm-cache")))
	fmt.Fprintf(&b, "  <projectFiles>\n    <directory name=\"%s\"/>\n", html.EscapeString(env.SourceDir))
	if dirs := excludedDirs(env.SourceDir, scanner.AllExcludes(s), 500); len(dirs) > 0 {
		b.WriteString("    <ignoreFiles>\n")
		for _, d := range dirs {
			fmt.Fprintf(&b, "      <directory name=\"%s\"/>\n", html.EscapeString(d))
		}
		b.WriteString("    </ignoreFiles>\n")
	}
	b.WriteString("  </projectFiles>\n")
	b.WriteString("  <enableExtensions><extension name=\"pdo\"/><extension name=\"mysqli\"/></enableExtensions>\n</psalm>\n")
	return b.String()
}

// Command implements scanner.Scanner. The config is generated per scan in
// the scratch directory; the repository's own psalm.xml is not used.
func (Psalm) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	cfg := filepath.Join(env.TmpDir, "psalm.xml")
	if err := os.MkdirAll(psalmRoot(env), 0o700); err != nil {
		return scanner.Cmd{Path: "false"}
	}
	if err := os.WriteFile(cfg, []byte(psalmConfig(env, s)), 0o600); err != nil {
		return scanner.Cmd{Path: "false"}
	}
	return scanner.Cmd{
		Path: "psalm",
		Args: []string{
			"-c", cfg, "--root=" + psalmRoot(env), "--taint-analysis", "--no-cache", "--threads=1",
			"--no-progress", "--monochrome", "--output-format=compact", "--report=" + filepath.Join(env.OutDir, "psalm.sarif"),
		},
		// Psalm prints a table of every issue; the SARIF report is what counts.
		StdoutFile:  filepath.Join(env.TmpDir, "psalm.txt"),
		OKExitCodes: []int{0, 1, 2},
	}
}

// psalmMedium are taint kinds whose impact depends on context (output
// encoding, headers); the rest (SQL, shell, include, eval, unserialize,
// file, SSRF...) are high.
var psalmMedium = map[string]bool{
	"TaintedHtml": true, "TaintedTextWithQuotes": true, "TaintedHeader": true, "TaintedCookie": true,
	"TaintedUserSecret": true, "TaintedSystemSecret": true,
}

func psalmSeverity(_ sarif.Result, rule *sarif.Rule) finding.Severity {
	if rule != nil && psalmMedium[rule.Name] {
		return finding.Medium
	}
	return finding.High
}

// Parse implements scanner.Scanner. Psalm writes paths relative to its
// root; they are made absolute so normalisation relativises them to the
// repository.
func (Psalm) Parse(env scanner.Env) ([]finding.Finding, error) {
	found, err := readSARIF(env, "psalm.sarif", sarif.Options{
		Tool: "psalm", Category: finding.CategorySAST, Severity: psalmSeverity, RuleIDFromName: true,
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	for i := range found {
		if f := found[i].File; f != "" && !filepath.IsAbs(f) {
			found[i].File = filepath.Clean(filepath.Join(psalmRoot(env), filepath.FromSlash(f)))
		}
	}
	return found, err
}
