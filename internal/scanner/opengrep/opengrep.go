// Package opengrep adapts Opengrep (LGPL Semgrep CE fork) running the scanX
// rule bundle (ADR-003). Only local rule directories are used: never registry
// configs, which would need network and carry restrictive rule licenses.
package opengrep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

const (
	outFile = "opengrep.json"
	// fullProfileDir mirrors rules.FullProfileDir (kept here to avoid a dependency).
	fullProfileDir = "_full"
)

// Scanner is the Opengrep adapter.
type Scanner struct{}

func init() { scanner.Register(Scanner{}) }

// ID implements scanner.Scanner.
func (Scanner) ID() string { return "opengrep" }

// Name implements scanner.Scanner.
func (Scanner) Name() string { return "Opengrep (multi-language SAST)" }

// Tool implements scanner.Scanner.
func (Scanner) Tool() string { return "opengrep" }

// Category implements scanner.Scanner.
func (Scanner) Category() finding.Category { return finding.CategorySAST }

// Applies implements scanner.Scanner.
func (Scanner) Applies(*detect.Result, scanner.Settings) bool { return true }

// Timeout implements scanner.Scanner.
func (Scanner) Timeout(s scanner.Settings) time.Duration {
	if s.SASTTimeout > 0 {
		return s.SASTTimeout
	}
	return scanner.DefaultSASTTimeout
}

// VersionCmd implements scanner.VersionReporter.
func (Scanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "opengrep", Args: []string{"--version"}, Env: cacheEnv("")}
}

// cacheEnv points Opengrep at the cache unpacked at image build time so it
// never needs to write next to its binary.
func cacheEnv(toolHome string) []string {
	if toolHome == "" {
		toolHome = os.Getenv("SCANX_TOOL_HOME")
	}
	if toolHome == "" {
		return nil
	}
	return []string{"XDG_CACHE_HOME=" + filepath.Join(toolHome, ".cache")}
}

// configDirs lists the rule directories to pass with --config.
func configDirs(rulesDir, profile string) []string {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return []string{rulesDir}
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == fullProfileDir {
			if profile == "full" {
				dirs = append(dirs, filepath.Join(rulesDir, e.Name()))
			}
			continue
		}
		dirs = append(dirs, filepath.Join(rulesDir, e.Name()))
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		return []string{rulesDir}
	}
	return dirs
}

// Command implements scanner.Scanner.
func (Scanner) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	var args []string
	args = append(args, "scan")
	for _, d := range configDirs(env.RulesDir, s.Profile) {
		args = append(args, "--config", d)
	}
	args = append(args,
		"--json-output="+filepath.Join(env.OutDir, outFile),
		"--quiet",
		"--taint-intrafile",
		// A .semgrepignore inside the repository must not hide files.
		"--x-ignore-semgrepignore-files",
		"--timeout", "30",
		"--max-target-bytes", "5000000",
	)
	excludes := append(append(append([]string{}, scanner.DefaultExcludes...), scanner.SASTExcludes...), s.Exclude...)
	for _, ex := range excludes {
		args = append(args, "--exclude", ex)
	}
	args = append(args, env.SourceDir)
	return scanner.Cmd{Path: "opengrep", Args: args, Env: cacheEnv(env.ToolHome)}
}

type output struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string   `json:"message"`
			Severity string   `json:"severity"`
			Metadata metadata `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"errors"`
}

type metadata struct {
	CWE        stringList `json:"cwe"`
	OWASP      stringList `json:"owasp"`
	Confidence string     `json:"confidence"`
	References stringList `json:"references"`
	Category   string     `json:"category"`
}

// stringList accepts a JSON string or array of strings (rule metadata varies).
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		*s = nil
		return nil //nolint:nilerr // unexpected metadata shapes are ignored
	}
	*s = many
	return nil
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
	var o output
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("opengrep json: %w", err)
	}
	out := make([]finding.Finding, 0, len(o.Results))
	for _, r := range o.Results {
		sev, _ := finding.FromVendor(r.Extra.Severity)
		md := r.Extra.Metadata
		conf := strings.ToLower(md.Confidence)
		if conf == "low" && sev > finding.Low {
			sev-- // low-confidence rules are demoted one step
		}
		out = append(out, finding.Finding{
			Tool:        "opengrep",
			RuleID:      displayRule(r.CheckID),
			Category:    finding.CategorySAST,
			Severity:    sev,
			Confidence:  conf,
			Title:       firstSentence(r.Extra.Message),
			Description: strings.TrimSpace(r.Extra.Message),
			CWE:         finding.NormalizeCWEs(md.CWE...),
			OWASP:       finding.NormalizeOWASP(md.OWASP...),
			File:        r.Path,
			StartLine:   r.Start.Line,
			EndLine:     r.End.Line,
			References:  limit(md.References, 5),
		})
	}
	return out, nil
}

// displayRule strips the path-derived prefix Opengrep adds to rule ids
// ("opt.scanx.rules.scanx.php.scanx-php-sqli" → "scanx.php.scanx-php-sqli").
func displayRule(id string) string {
	for _, p := range []string{"opt.scanx.rules._full.", "opt.scanx.rules.", "rules."} {
		if strings.HasPrefix(id, p) {
			return strings.TrimPrefix(id, p)
		}
	}
	return id
}

func firstSentence(msg string) string {
	msg = strings.TrimSpace(strings.ReplaceAll(msg, "\n", " "))
	if i := strings.Index(msg, ". "); i > 0 && i < 200 {
		return msg[:i+1]
	}
	if len([]rune(msg)) > 200 {
		return string([]rune(msg)[:200]) + "…"
	}
	return msg
}

func limit(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
