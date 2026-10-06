package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/ininia/scanx/internal/finding"
)

// SARIF 2.1.0 subset used for GitHub Code Scanning uploads.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Help             *sarifText     `json:"help,omitempty"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// securitySeverity is the numeric score GitHub uses to rank alerts.
var securitySeverity = map[finding.Severity]string{
	finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "2.0", finding.Info: "0.0",
}

func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes one SARIF run ("scanX") with one result per issue.
// GitHub Code Scanning requires a file location, so issues without one are
// left out of SARIF (they remain in the JSON/HTML reports).
func (r *Report) WriteSARIF(w io.Writer) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, is := range r.Issues {
		if is.File == "" {
			continue
		}
		p := is.Findings[0]
		ruleID := p.Tool + "/" + p.RuleID
		if _, ok := rules[ruleID]; !ok {
			tags := append([]string{"security", string(is.Category)}, is.CWE...)
			rule := sarifRule{
				ID:               ruleID,
				Name:             p.RuleID,
				ShortDescription: sarifText{Text: firstLine(p.Title)},
				Properties: map[string]any{
					"tags":              tags,
					"security-severity": securitySeverity[is.Severity],
					"precision":         precision(is.Confidence),
				},
			}
			if p.Description != "" {
				rule.FullDescription = &sarifText{Text: p.Description}
			}
			if len(p.References) > 0 {
				rule.HelpURI = p.References[0]
			}
			if p.Remediation != "" {
				rule.Help = &sarifText{Text: p.Remediation}
			}
			rules[ruleID] = rule
		}
		loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: is.File}}}
		if is.StartLine > 0 {
			end := p.EndLine
			if end < is.StartLine {
				end = 0
			}
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: is.StartLine, EndLine: end}
		}
		msg := is.Title
		if len(is.Sources) > 1 {
			msg += " (reported by " + strings.Join(is.Sources, ", ") + ")"
		}
		results = append(results, sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(is.Severity),
			Message:             sarifText{Text: msg},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{"scanx/v1": is.Fingerprint},
			Properties:          map[string]any{"severity": is.Severity.String(), "sources": is.Sources, "category": is.Category},
		})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rl := range rules {
		ruleList = append(ruleList, rl)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "scanX", InformationURI: "https://github.com/ininia/scanx", Version: r.Version, Rules: ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func precision(conf string) string {
	switch strings.ToLower(conf) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
