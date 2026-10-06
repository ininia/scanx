package finding

import (
	"sort"
	"strings"
)

// Issue groups findings from one or more tools that describe the same problem.
type Issue struct {
	Fingerprint string      `json:"fingerprint"`
	Category    Category    `json:"category"`
	Severity    Severity    `json:"severity"`
	Confidence  string      `json:"confidence,omitempty"`
	Title       string      `json:"title"`
	File        string      `json:"file,omitempty"`
	StartLine   int         `json:"start_line,omitempty"`
	CWE         []string    `json:"cwe,omitempty"`
	CVE         []string    `json:"cve,omitempty"`
	Package     *PackageRef `json:"package,omitempty"`
	Sources     []string    `json:"sources"`
	Findings    []Finding   `json:"findings"`
}

// toolPriority decides which finding represents a merged issue (lower wins).
// Specialized tools beat generic ones so titles and fingerprints are stable.
var toolPriority = map[string]int{
	"gitleaks": 0, "trivy": 1, "osv-scanner": 2, "opengrep": 3, "semgrep": 4,
}

func priority(tool string) int {
	if p, ok := toolPriority[tool]; ok {
		return p
	}
	return 100
}

// Group merges findings into issues (spec §7.4):
//   - identical fingerprints are always merged;
//   - SAST/IaC findings in the same file within ±2 lines sharing a CWE merge;
//   - SCA findings sharing a CVE/ID for the same package and version merge.
//
// Fingerprints must already be set. Output is sorted by severity (desc),
// then file, line and title, so reports are deterministic.
func Group(findings []Finding) []Issue {
	n := len(findings)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	byFP := map[string]int{}
	byPkgID := map[string]int{}
	for i := range findings {
		f := &findings[i]
		if j, ok := byFP[f.Fingerprint]; ok {
			union(j, i)
		} else {
			byFP[f.Fingerprint] = i
		}
		if f.Category == CategorySCA && f.Package != nil {
			for _, id := range append(append([]string(nil), f.CVE...), f.RuleID) {
				key := strings.ToLower(id + "|" + f.Package.Name + "|" + f.Package.Version)
				if j, ok := byPkgID[key]; ok {
					union(j, i)
				} else {
					byPkgID[key] = i
				}
			}
		}
	}
	// Location + CWE merge (quadratic per file; files rarely have many findings).
	byFile := map[string][]int{}
	for i := range findings {
		f := &findings[i]
		if f.File != "" && len(f.CWE) > 0 && (f.Category == CategorySAST || f.Category == CategoryIaC) {
			byFile[f.File] = append(byFile[f.File], i)
		}
	}
	for _, idx := range byFile {
		for a := 0; a < len(idx); a++ {
			for b := a + 1; b < len(idx); b++ {
				fa, fb := &findings[idx[a]], &findings[idx[b]]
				if abs(fa.StartLine-fb.StartLine) <= 2 && shareAny(fa.CWE, fb.CWE) {
					union(idx[a], idx[b])
				}
			}
		}
	}

	groups := map[int][]int{}
	for i := range findings {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	issues := make([]Issue, 0, len(groups))
	for _, idx := range groups {
		issues = append(issues, buildIssue(findings, idx))
	}
	sort.Slice(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.Title < b.Title
	})
	return issues
}

func buildIssue(all []Finding, idx []int) Issue {
	members := make([]Finding, 0, len(idx))
	for _, i := range idx {
		members = append(members, all[i])
	}
	sort.SliceStable(members, func(i, j int) bool {
		pi, pj := priority(members[i].Tool), priority(members[j].Tool)
		if pi != pj {
			return pi < pj
		}
		if members[i].Severity != members[j].Severity {
			return members[i].Severity > members[j].Severity
		}
		return members[i].Fingerprint < members[j].Fingerprint
	})
	p := members[0]
	is := Issue{
		Fingerprint: p.Fingerprint,
		Category:    p.Category,
		Severity:    p.Severity,
		Confidence:  p.Confidence,
		Title:       p.Title,
		File:        p.File,
		StartLine:   p.StartLine,
		Package:     p.Package,
		Findings:    members,
	}
	tools := map[string]bool{}
	for _, m := range members {
		if m.Severity > is.Severity {
			is.Severity = m.Severity
		}
		tools[m.Tool] = true
		is.CWE = mergeUnique(is.CWE, m.CWE)
		is.CVE = mergeUnique(is.CVE, m.CVE)
	}
	for t := range tools {
		is.Sources = append(is.Sources, t)
	}
	sort.Strings(is.Sources)
	if len(is.Sources) > 1 {
		is.Confidence = "high" // independent tools agree
	}
	return is
}

func mergeUnique(dst, src []string) []string {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d == s {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

func shareAny(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
