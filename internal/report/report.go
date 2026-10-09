// Package report turns scan results into the scanX report: summary, score,
// quality gate and JSON / SARIF / HTML renderings.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/version"
)

// SchemaVersion of the JSON report; bump on breaking changes.
const SchemaVersion = 1

// Report is the complete, self-describing scan report.
type Report struct {
	SchemaVersion int              `json:"schema_version"`
	Tool          string           `json:"tool"`
	Version       string           `json:"version"`
	Target        Target           `json:"target"`
	StartedAt     time.Time        `json:"started_at"`
	FinishedAt    time.Time        `json:"finished_at"`
	DurationSec   float64          `json:"duration_seconds"`
	Partial       bool             `json:"partial"`
	Detected      *detect.Result   `json:"detected,omitempty"`
	Tools         []engine.ToolRun `json:"tools"`
	Summary       Summary          `json:"summary"`
	Score         int              `json:"score"`
	Grade         string           `json:"grade"`
	Categories    []CategoryScore  `json:"score_categories"`
	Gate          Gate             `json:"gate"`
	Warnings      []string         `json:"warnings,omitempty"`
	Issues        []finding.Issue  `json:"issues"`
}

// Target identifies what was scanned.
type Target struct {
	Path   string `json:"path,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// Summary counts issues.
type Summary struct {
	Critical   int            `json:"critical"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	Info       int            `json:"info"`
	Total      int            `json:"total"`
	ByCategory map[string]int `json:"by_category"`
	ByTool     map[string]int `json:"by_tool"`
}

// Count returns the number of issues at severity s.
func (s Summary) Count(sev finding.Severity) int {
	switch sev {
	case finding.Critical:
		return s.Critical
	case finding.High:
		return s.High
	case finding.Medium:
		return s.Medium
	case finding.Low:
		return s.Low
	default:
		return s.Info
	}
}

// Gate is the quality gate verdict.
type Gate struct {
	Result  string   `json:"result"` // pass | fail
	Policy  string   `json:"policy"`
	Reasons []string `json:"reasons,omitempty"`
}

// Policy decides the gate. Thresholds: the gate fails when the number of
// issues at a severity exceeds the threshold (spec appendix B); a nil entry
// means "no limit". FailOn is a shortcut: any issue ≥ FailOn fails.
type Policy struct {
	FailOn     *finding.Severity
	Thresholds map[finding.Severity]int
}

// ParseFailOn parses the --fail-on flag ("none" disables the gate).
func ParseFailOn(s string) (Policy, error) {
	if strings.EqualFold(s, "none") || s == "" {
		return Policy{}, nil
	}
	sev, err := finding.ParseSeverity(s)
	if err != nil {
		return Policy{}, fmt.Errorf("--fail-on must be critical|high|medium|low|info|none")
	}
	return Policy{FailOn: &sev}, nil
}

func (p Policy) String() string {
	var parts []string
	if p.FailOn != nil {
		parts = append(parts, "fail on "+p.FailOn.String()+" or higher")
	}
	sevs := make([]finding.Severity, 0, len(p.Thresholds))
	for s := range p.Thresholds {
		sevs = append(sevs, s)
	}
	sort.Slice(sevs, func(i, j int) bool { return sevs[i] > sevs[j] })
	for _, s := range sevs {
		parts = append(parts, fmt.Sprintf("%s>%d", s, p.Thresholds[s]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " OR ")
}

// Evaluate applies the policy to a summary.
func (p Policy) Evaluate(s Summary) Gate {
	g := Gate{Result: "pass", Policy: p.String()}
	for sev := finding.Critical; sev >= finding.Info; sev-- {
		n := s.Count(sev)
		if n == 0 {
			continue
		}
		if p.FailOn != nil && sev >= *p.FailOn {
			g.Reasons = append(g.Reasons, fmt.Sprintf("%s=%d", sev, n))
			continue
		}
		if limit, ok := p.Thresholds[sev]; ok && n > limit {
			g.Reasons = append(g.Reasons, fmt.Sprintf("%s=%d>%d", sev, n, limit))
		}
	}
	if len(g.Reasons) > 0 {
		g.Result = "fail"
	}
	return g
}

// Summarize counts issues.
func Summarize(issues []finding.Issue) Summary {
	s := Summary{ByCategory: map[string]int{}, ByTool: map[string]int{}}
	for _, is := range issues {
		switch is.Severity {
		case finding.Critical:
			s.Critical++
		case finding.High:
			s.High++
		case finding.Medium:
			s.Medium++
		case finding.Low:
			s.Low++
		default:
			s.Info++
		}
		s.Total++
		s.ByCategory[string(is.Category)]++
		for _, t := range is.Sources {
			s.ByTool[t]++
		}
	}
	return s
}

// Build assembles a report from an engine result.
func Build(res *engine.Result, target Target, started, finished time.Time, p Policy) *Report {
	issues := finding.Group(res.Findings)
	sum := Summarize(issues)
	r := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          "scanx",
		Version:       version.Version,
		Target:        target,
		StartedAt:     started.UTC(),
		FinishedAt:    finished.UTC(),
		DurationSec:   math.Round(finished.Sub(started).Seconds()*10) / 10,
		Partial:       res.Partial,
		Detected:      res.Detection,
		Tools:         res.Tools,
		Summary:       sum,
		Gate:          p.Evaluate(sum),
		Issues:        issues,
	}
	card := Score(issues, res.Tools)
	r.Score, r.Grade, r.Categories = card.Score, card.Grade, card.Categories
	if r.Partial {
		r.Warnings = append(r.Warnings, "Some scanners failed; results are partial.")
	}
	if res.Detection != nil && len(res.Detection.Ecosystems) > 0 && !hasLockfile(res.Detection.Lockfiles) {
		r.Warnings = append(r.Warnings, "No dependency lock file found; dependency analysis is incomplete.")
	}
	return r
}

func hasLockfile(files []string) bool {
	for _, f := range files {
		l := strings.ToLower(f)
		if strings.HasSuffix(l, ".lock") || strings.HasSuffix(l, "lock.json") || strings.HasSuffix(l, "lock.yaml") ||
			strings.HasSuffix(l, "go.sum") || strings.HasSuffix(l, ".lockfile") || strings.HasSuffix(l, "requirements.txt") {
			return true
		}
	}
	return false
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
