// Package gitleaks adapts Gitleaks for the working tree ("dir") and the git
// history ("git"). Gitleaks always runs with --redact and with scanX's own
// config, so a repository cannot disable rules via .gitleaks.toml.
package gitleaks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// Mode selects what Gitleaks scans.
type Mode string

// Modes.
const (
	ModeDir Mode = "dir"
	ModeGit Mode = "git"
)

// Scanner is the Gitleaks adapter for one mode.
type Scanner struct{ Mode Mode }

func init() {
	scanner.Register(Scanner{Mode: ModeDir})
	scanner.Register(Scanner{Mode: ModeGit})
}

// ID implements scanner.Scanner.
func (s Scanner) ID() string { return "gitleaks-" + string(s.Mode) }

// Name implements scanner.Scanner.
func (s Scanner) Name() string {
	if s.Mode == ModeGit {
		return "Gitleaks (git history)"
	}
	return "Gitleaks (working tree)"
}

// Tool implements scanner.Scanner.
func (Scanner) Tool() string { return "gitleaks" }

// Category implements scanner.Scanner.
func (Scanner) Category() finding.Category { return finding.CategorySecret }

// Applies implements scanner.Scanner.
func (s Scanner) Applies(d *detect.Result, st scanner.Settings) bool {
	if s.Mode == ModeGit {
		return d.HasGit && st.History && st.Profile != "fast"
	}
	return true
}

// Timeout implements scanner.Scanner.
func (s Scanner) Timeout(scanner.Settings) time.Duration {
	if s.Mode == ModeGit {
		return 20 * time.Minute
	}
	return 10 * time.Minute
}

// VersionCmd implements scanner.VersionReporter.
func (Scanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "gitleaks", Args: []string{"version"}}
}

func (s Scanner) outFile() string { return "gitleaks-" + string(s.Mode) + ".json" }

// Command implements scanner.Scanner.
func (s Scanner) Command(env scanner.Env, _ scanner.Settings) scanner.Cmd {
	args := []string{
		string(s.Mode), env.SourceDir,
		"-c", filepath.Join(env.ConfigDir, "gitleaks.toml"),
		"-i", filepath.Join(env.ConfigDir, "gitleaksignore"),
		"-f", "json", "-r", filepath.Join(env.OutDir, s.outFile()),
		"--redact", "--no-banner", "--exit-code", "0", "--max-target-megabytes", "10",
	}
	cmd := scanner.Cmd{Path: "gitleaks"}
	if s.Mode == ModeGit {
		args = append(args, "--log-opts=--all")
		// The checkout is owned by another uid and mounted read-only; allow it
		// without writing a git config file.
		cmd.Env = []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*"}
	}
	cmd.Args = args
	return cmd
}

type leak struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Match       string   `json:"Match"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
}

// Parse implements scanner.Scanner.
func (s Scanner) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, s.outFile()))
	if err != nil {
		return nil, err
	}
	return s.parse(data)
}

func (s Scanner) parse(data []byte) ([]finding.Finding, error) {
	var leaks []leak
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks json: %w", err)
	}
	out := make([]finding.Finding, 0, len(leaks))
	for _, l := range leaks {
		f := finding.Finding{
			Tool:        "gitleaks",
			RuleID:      l.RuleID,
			Category:    finding.CategorySecret,
			Severity:    finding.SecretSeverity(l.RuleID, false),
			Confidence:  "medium",
			Title:       "Secret detected: " + l.RuleID,
			Description: l.Description,
			CWE:         []string{"CWE-798"},
			File:        finding.CleanPath(l.File),
			StartLine:   l.StartLine,
			EndLine:     l.EndLine,
			Remediation: "Revoke and rotate the credential, remove it from the code and load it from a secret store or environment variable.",
		}
		if s.Mode == ModeGit {
			f.Title = "Secret in git history: " + l.RuleID
			if len(l.Commit) >= 12 {
				f.Description += " (commit " + l.Commit[:12] + ")"
			}
			// Snippets come from the current tree, which may not contain the
			// historical line; the redacted match is the identity instead.
			f.StartLine, f.EndLine = 0, 0
		}
		// Match is redacted by gitleaks; it makes dir and git findings of the
		// same secret share a fingerprint.
		f.SetMatchLines(finding.MaskText(l.Match))
		out = append(out, f)
	}
	return out, nil
}

// PostProcess (git mode) drops history findings that duplicate a working
// tree finding and downgrades the rest to "history only" severity (§7.5).
func (s Scanner) PostProcess(all []finding.Finding) []finding.Finding {
	if s.Mode != ModeGit {
		return all
	}
	current := map[string]bool{}
	for i := range all {
		f := &all[i]
		if f.Category == finding.CategorySecret && f.Tool == "gitleaks" && f.StartLine > 0 {
			current[f.File+"|"+f.RuleID] = true
		}
	}
	out := all[:0]
	for _, f := range all {
		if f.Tool == "gitleaks" && f.StartLine == 0 && f.Category == finding.CategorySecret {
			if current[f.File+"|"+f.RuleID] {
				continue // still present in the working tree, reported there
			}
			f.Severity = finding.SecretSeverity(f.RuleID, true)
		}
		out = append(out, f)
	}
	return out
}
