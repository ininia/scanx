// Package sarif turns SARIF 2.1.0 output of any analyser into scanX
// findings. Tool adapters supply the category and, when the tool encodes
// severity in its own way, a severity function.
package sarif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/finding"
)

// Log is the subset of SARIF scanX reads.
type Log struct {
	Runs []Run `json:"runs"`
}

// Run is one tool run.
type Run struct {
	Tool struct {
		Driver struct {
			Name  string `json:"name"`
			Rules []Rule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []Result `json:"results"`
}

// Rule describes a check.
type Rule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription *Text      `json:"shortDescription"`
	FullDescription  *Text      `json:"fullDescription"`
	Help             *Text      `json:"help"`
	HelpURI          string     `json:"helpUri"`
	Properties       Properties `json:"properties"`
	DefaultConfig    *struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

// Text is a SARIF message.
type Text struct {
	Text string `json:"text"`
}

// Properties is a SARIF property bag.
type Properties map[string]any

// Result is one finding.
type Result struct {
	RuleID     string     `json:"ruleId"`
	RuleIndex  *int       `json:"ruleIndex"`
	Level      string     `json:"level"`
	Message    Text       `json:"message"`
	Locations  []Location `json:"locations"`
	Properties Properties `json:"properties"`
}

// Location is where a result was found.
type Location struct {
	Physical struct {
		Artifact struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			EndLine   int `json:"endLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// SeverityFunc decides a finding's severity from the result and its rule.
type SeverityFunc func(r Result, rule *Rule) finding.Severity

// Options configure Parse.
type Options struct {
	Tool     string
	Category finding.Category
	Severity SeverityFunc // nil = DefaultSeverity
}

// DefaultSeverity uses the "security-severity" score (GitHub convention:
// ≥9 critical, ≥7 high, ≥4 medium, >0 low) and falls back to the SARIF
// level: error → medium, warning → low, note/none → info.
func DefaultSeverity(r Result, rule *Rule) finding.Severity {
	for _, props := range []Properties{r.Properties, ruleProps(rule)} {
		if s, ok := number(props["security-severity"]); ok {
			return fromScore(s)
		}
	}
	return FromLevel(level(r, rule))
}

// FromLevel maps a SARIF level conservatively (linters use "error" freely).
func FromLevel(l string) finding.Severity {
	switch strings.ToLower(l) {
	case "error":
		return finding.Medium
	case "warning":
		return finding.Low
	default:
		return finding.Info
	}
}

func fromScore(s float64) finding.Severity {
	switch {
	case s >= 9:
		return finding.Critical
	case s >= 7:
		return finding.High
	case s >= 4:
		return finding.Medium
	case s > 0:
		return finding.Low
	}
	return finding.Info
}

func level(r Result, rule *Rule) string {
	if r.Level != "" {
		return r.Level
	}
	if rule != nil && rule.DefaultConfig != nil {
		return rule.DefaultConfig.Level
	}
	return "warning"
}

func ruleProps(rule *Rule) Properties {
	if rule == nil {
		return nil
	}
	return rule.Properties
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}

var cweRe = regexp.MustCompile(`(?i)cwe[-_/ ]?(\d+)`)

// cwes collects CWE ids from rule tags and properties.
func cwes(rule *Rule) []string {
	if rule == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var add func(v any)
	add = func(v any) {
		switch x := v.(type) {
		case string:
			for _, m := range cweRe.FindAllStringSubmatch(x, -1) {
				id := "CWE-" + m[1]
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
		case []any:
			for _, e := range x {
				add(e)
			}
		}
	}
	add(rule.Properties["tags"])
	add(rule.Properties["cwe"])
	return out
}

func text(t *Text) string {
	if t == nil {
		return ""
	}
	return strings.TrimSpace(t.Text)
}

// Parse converts a SARIF document.
func Parse(data []byte, opt Options) ([]finding.Finding, error) {
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("%s sarif: %w", opt.Tool, err)
	}
	sev := opt.Severity
	if sev == nil {
		sev = DefaultSeverity
	}
	var out []finding.Finding
	for _, run := range log.Runs {
		byID := map[string]*Rule{}
		for i := range run.Tool.Driver.Rules {
			byID[run.Tool.Driver.Rules[i].ID] = &run.Tool.Driver.Rules[i]
		}
		for _, r := range run.Results {
			var rule *Rule
			if r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = &run.Tool.Driver.Rules[*r.RuleIndex]
			} else {
				rule = byID[r.RuleID]
			}
			f := finding.Finding{
				Tool: opt.Tool, RuleID: r.RuleID, Category: opt.Category, Severity: sev(r, rule),
				Title: firstLine(r.Message.Text), CWE: cwes(rule),
			}
			if rule != nil {
				if t := text(rule.ShortDescription); t != "" {
					f.Title = t
				}
				f.Description = firstNonEmpty(text(rule.FullDescription), r.Message.Text)
				f.Remediation = text(rule.Help)
				if rule.HelpURI != "" {
					f.References = []string{rule.HelpURI}
				}
			}
			if f.Title == "" {
				f.Title = r.RuleID
			}
			if f.Description == "" || f.Description == f.Title {
				f.Description = r.Message.Text
			}
			if len(r.Locations) > 0 {
				loc := r.Locations[0].Physical
				f.File = strings.TrimPrefix(loc.Artifact.URI, "file://")
				f.StartLine, f.EndLine = loc.Region.StartLine, loc.Region.EndLine
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
