package extra

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// ---------- ShellCheck ----------

// ShellCheck finds bugs and unsafe constructs in shell scripts.
type ShellCheck struct{}

// ID implements scanner.Scanner.
func (ShellCheck) ID() string { return "shellcheck" }

// Name implements scanner.Scanner.
func (ShellCheck) Name() string { return "ShellCheck (shell scripts)" }

// Tool implements scanner.Scanner.
func (ShellCheck) Tool() string { return "shellcheck" }

// Category implements scanner.Scanner.
func (ShellCheck) Category() finding.Category { return finding.CategoryQuality }

// Applies implements scanner.Scanner.
func (ShellCheck) Applies(d *detect.Result, _ scanner.Settings) bool {
	return hasAny(d, "shell", "bash", "sh")
}

// Timeout implements scanner.Scanner.
func (ShellCheck) Timeout(scanner.Settings) time.Duration { return 5 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (ShellCheck) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "shellcheck", Args: []string{"--version"}}
}

func isShell(_, name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".sh") || strings.HasSuffix(l, ".bash")
}

// Command implements scanner.Scanner.
func (ShellCheck) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	out := filepath.Join(env.OutDir, "shellcheck.json")
	files := scanner.FindFiles(env.SourceDir, scanner.AllExcludes(s), 2000, isShell)
	if len(files) == 0 {
		return scanner.Cmd{Path: "true", StdoutFile: out}
	}
	return scanner.Cmd{
		Path: "shellcheck", Args: append([]string{"--format", "json1", "--severity", "warning", "--external-sources=false"}, files...),
		StdoutFile: out, OKExitCodes: []int{0, 1},
	}
}

// Parse implements scanner.Scanner.
func (ShellCheck) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, "shellcheck.json")) //nolint:gosec // our output dir
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var out struct {
		Comments []struct {
			File    string `json:"file"`
			Line    int    `json:"line"`
			EndLine int    `json:"endLine"`
			Level   string `json:"level"`
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"comments"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("shellcheck json: %w", err)
	}
	fs := make([]finding.Finding, 0, len(out.Comments))
	for _, c := range out.Comments {
		sev := finding.Low
		if c.Level == "error" {
			sev = finding.Medium
		}
		code := "SC" + strconv.Itoa(c.Code)
		fs = append(fs, finding.Finding{
			Tool: "shellcheck", RuleID: code, Category: finding.CategoryQuality, Severity: sev,
			Title: code + ": " + c.Message, Description: c.Message, File: c.File, StartLine: c.Line, EndLine: c.EndLine,
			References: []string{"https://www.shellcheck.net/wiki/" + code},
		})
	}
	return fs, nil
}

// ---------- Lizard ----------

// Lizard measures cyclomatic complexity and length of every function.
// Only functions above the thresholds become (quality) findings.
type Lizard struct{}

// Complexity thresholds (cyclomatic complexity, CCN).
const (
	ccnLow    = 20 // hard to test
	ccnMedium = 35 // very hard to change safely
	ccnHigh   = 60 // untestable
	nlocLong  = 300
)

// ID implements scanner.Scanner.
func (Lizard) ID() string { return "lizard" }

// Name implements scanner.Scanner.
func (Lizard) Name() string { return "Lizard (code complexity)" }

// Tool implements scanner.Scanner.
func (Lizard) Tool() string { return "lizard" }

// Category implements scanner.Scanner.
func (Lizard) Category() finding.Category { return finding.CategoryQuality }

// Applies implements scanner.Scanner.
func (Lizard) Applies(d *detect.Result, _ scanner.Settings) bool { return hasAny(d, codeLanguages...) }

// Timeout implements scanner.Scanner.
func (Lizard) Timeout(scanner.Settings) time.Duration { return 15 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Lizard) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "lizard", Args: []string{"--version"}}
}

// Command implements scanner.Scanner.
func (Lizard) Command(env scanner.Env, s scanner.Settings) scanner.Cmd {
	args := []string{"--csv", "--working_threads", "2"}
	for _, ex := range scanner.AllExcludes(s) {
		if strings.Contains(ex, "/") || !strings.ContainsAny(ex, "*?") {
			args = append(args, "--exclude", "*/"+ex+"/*")
		} else {
			args = append(args, "--exclude", "*/"+ex)
		}
	}
	args = append(args, env.SourceDir)
	return scanner.Cmd{Path: "lizard", Args: args, StdoutFile: filepath.Join(env.OutDir, "lizard.csv")}
}

// Parse implements scanner.Scanner. CSV columns: NLOC, CCN, tokens, params,
// length, location, file, function, long_name, start, end.
func (Lizard) Parse(env scanner.Env) ([]finding.Finding, error) {
	f, err := os.Open(filepath.Join(env.OutDir, "lizard.csv")) //nolint:gosec // our output dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	var fs []finding.Finding
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("lizard csv: %w", err)
		}
		if len(rec) < 11 {
			continue
		}
		nloc, _ := strconv.Atoi(rec[0])
		ccn, err := strconv.Atoi(rec[1])
		if err != nil {
			continue // header or garbage
		}
		start, _ := strconv.Atoi(rec[9])
		end, _ := strconv.Atoi(rec[10])
		fn := rec[7]
		var sev finding.Severity
		var rule, title string
		switch {
		case ccn >= ccnHigh:
			sev, rule = finding.High, "complexity"
		case ccn >= ccnMedium:
			sev, rule = finding.Medium, "complexity"
		case ccn >= ccnLow:
			sev, rule = finding.Low, "complexity"
		case nloc >= nlocLong:
			sev, rule = finding.Low, "long-function"
		default:
			continue
		}
		if rule == "complexity" {
			title = fmt.Sprintf("High cyclomatic complexity (%d) in %s", ccn, fn)
		} else {
			title = fmt.Sprintf("Very long function (%d lines) %s", nloc, fn)
		}
		fs = append(fs, finding.Finding{
			Tool: "lizard", RuleID: "lizard." + rule, Category: finding.CategoryQuality, Severity: sev,
			Title: title, File: rec[6], StartLine: start, EndLine: start,
			Description: fmt.Sprintf("Function %s: cyclomatic complexity %d, %d lines of code, %d parameters (lines %d-%d).",
				rec[8], ccn, nloc, atoi(rec[3]), start, end),
			Remediation: "Split the function into smaller ones; complex functions are hard to test and are where bugs and security issues hide.",
		})
	}
	return fs, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
