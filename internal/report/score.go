package report

import (
	"math"
	"strings"

	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
)

// Scoring (replaces spec §7.6's linear formula, which reached 0 with four
// critical or ten high issues and so said nothing about most real projects).
//
//  1. Issues are grouped per (category, rule, file): the same rule firing
//     fifty times in one file is one problem to fix, not fifty.
//  2. Each analysed category gets penalty points P = Σ severity weight and a
//     score 100 / (1 + P/50): one critical → 83, five high → 71, it falls
//     smoothly and never hits 0 for a single bad area.
//  3. The overall score is the weighted mean of the categories that were
//     actually analysed (a clean category contributes 100); categories whose
//     scanner did not run are left out instead of counting as clean.
var severityPoints = map[finding.Severity]float64{
	finding.Critical: 10, finding.High: 4, finding.Medium: 1, finding.Low: 0.2,
}

const scoreHalfAt = 50.0 // penalty points at which a category scores 50

// ScoreCategories in display order with their weight in the overall score.
// Code quality is shown but does not count towards the security score.
var ScoreCategories = []struct {
	ID     string
	Weight float64
}{{"sast", 35}, {"secret", 25}, {"sca", 25}, {"iac", 15}, {"quality", 0}}

// scoreCategory maps finding categories onto the scored ones.
func scoreCategory(c finding.Category) string {
	switch c {
	case finding.CategoryQuality:
		return "quality"
	case finding.CategorySAST, finding.CategoryDAST:
		return "sast"
	case finding.CategorySecret:
		return "secret"
	case finding.CategorySCA, finding.CategoryLicense:
		return "sca"
	case finding.CategoryIaC, finding.CategoryContainer:
		return "iac"
	}
	return "sast"
}

// toolCategories lists what each scanner analyses.
func toolCategories(toolID string) []string {
	switch {
	case strings.HasPrefix(toolID, "gitleaks"):
		return []string{"secret"}
	case strings.HasPrefix(toolID, "opengrep"), strings.HasPrefix(toolID, "semgrep"):
		return []string{"sast"}
	case strings.HasPrefix(toolID, "trivy"):
		return []string{"sca", "iac", "secret"}
	case strings.HasPrefix(toolID, "osv"):
		return []string{"sca"}
	case toolID == "devskim", toolID == "bandit":
		return []string{"sast"}
	case toolID == "checkov", toolID == "hadolint", toolID == "zizmor":
		return []string{"iac"}
	case toolID == "lizard", toolID == "shellcheck":
		return []string{"quality"}
	}
	return nil
}

// CategoryScore is the score of one analysed area.
type CategoryScore struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Groups   int    `json:"groups"` // distinct (rule, file) problems
	Analysed bool   `json:"analysed"`
	InGrade  bool   `json:"in_grade"` // counts towards the overall score
}

// ScoreCard is the overall score with its grade and per-category scores.
type ScoreCard struct {
	Score      int             `json:"score"`
	Grade      string          `json:"grade"`
	Categories []CategoryScore `json:"categories"`
}

// Grade turns a score into a letter.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	case score >= 20:
		return "E"
	default:
		return "F"
	}
}

// Score computes the score card. tools tells which categories were analysed
// (scanners with status ok); nil means "all categories".
func Score(issues []finding.Issue, tools []engine.ToolRun) ScoreCard {
	analysed := map[string]bool{}
	if tools == nil {
		for _, c := range ScoreCategories {
			analysed[c.ID] = true
		}
	}
	for _, t := range tools {
		if t.Status == engine.StatusOK {
			for _, c := range toolCategories(t.ID) {
				analysed[c] = true
			}
		}
	}
	type key struct{ cat, rule, file string }
	worst := map[key]finding.Severity{}
	for _, is := range issues {
		rule := is.Title
		if len(is.Findings) > 0 && is.Findings[0].RuleID != "" {
			rule = is.Findings[0].RuleID
		}
		k := key{scoreCategory(is.Category), rule, is.File}
		if s, ok := worst[k]; !ok || is.Severity > s {
			worst[k] = is.Severity
		}
		analysed[k.cat] = true // a finding proves the category was analysed
	}
	points := map[string]float64{}
	groups := map[string]int{}
	for k, sev := range worst {
		points[k.cat] += severityPoints[sev]
		groups[k.cat]++
	}
	card := ScoreCard{}
	var sum, weights float64
	for _, c := range ScoreCategories {
		cs := CategoryScore{Category: c.ID, Groups: groups[c.ID], Analysed: analysed[c.ID], InGrade: c.Weight > 0}
		v := 100 / (1 + points[c.ID]/scoreHalfAt)
		cs.Score = int(math.Round(v))
		if cs.Analysed && c.Weight > 0 {
			sum += v * c.Weight
			weights += c.Weight
		}
		card.Categories = append(card.Categories, cs)
	}
	card.Score = 100
	if weights > 0 {
		card.Score = int(math.Round(sum / weights))
	}
	card.Grade = Grade(card.Score)
	return card
}
