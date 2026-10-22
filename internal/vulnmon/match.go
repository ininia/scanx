package vulnmon

import (
	"archive/zip"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// Index is the inventory to match: ecosystem → package name → versions.
type Index map[string]map[string]map[string]bool

// Add puts one component into the index.
func (ix Index) Add(c Component) {
	if ix[c.Ecosystem] == nil {
		ix[c.Ecosystem] = map[string]map[string]bool{}
	}
	key := normName(c.Ecosystem, c.Name)
	if ix[c.Ecosystem][key] == nil {
		ix[c.Ecosystem][key] = map[string]bool{}
	}
	ix[c.Ecosystem][key][c.Version] = true
}

// normName folds names in ecosystems that compare them case-insensitively
// (PyPI also treats "_" and "." like "-").
func normName(eco, name string) string {
	switch eco {
	case "PyPI":
		return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name))
	case "NuGet", "Packagist", "npm":
		return strings.ToLower(name)
	}
	return name
}

// Key identifies a package version across inventory and advisories.
func Key(eco, name, version string) string {
	return eco + "\x00" + normName(eco, name) + "\x00" + version
}

// Match is one affected package version.
type Match struct {
	Ecosystem string
	Name      string
	Version   string
	VulnID    string
	Aliases   []string
	Summary   string
	Severity  string // critical | high | medium | low
	Fixed     string // first fixed version, if any
	Published string
}

// Record is the part of an OSV entry the matcher needs.
type Record struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Withdrawn string   `json:"withdrawn"`
	Published string   `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
		Versions         []string `json:"versions"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"affected"`
}

// MatchZip streams an OSV ecosystem export (all.zip) and returns the
// inventory versions it affects.
func MatchZip(path string, ix Index) ([]Match, int, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = zr.Close() }()
	var out []Match
	n := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 32<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var rec Record
		err = json.NewDecoder(io.LimitReader(rc, 32<<20)).Decode(&rec)
		_ = rc.Close()
		if err != nil {
			continue
		}
		n++
		out = append(out, MatchRecord(&rec, ix)...)
	}
	return out, n, nil
}

// MatchRecord checks one advisory against the inventory.
func MatchRecord(rec *Record, ix Index) []Match {
	if rec.Withdrawn != "" {
		return nil
	}
	var out []Match
	for _, a := range rec.Affected {
		eco := ecosystemBase(a.Package.Ecosystem)
		versions := ix[eco][normName(eco, a.Package.Name)]
		if len(versions) == 0 {
			continue
		}
		listed := map[string]bool{}
		for _, v := range a.Versions {
			listed[v] = true
		}
		for v := range versions {
			affected, fixed := listed[v], ""
			if !affected {
				affected, fixed = inRanges(eco, v, a.Ranges)
			} else {
				_, fixed = inRanges(eco, v, a.Ranges)
			}
			if !affected {
				continue
			}
			sev := severityOf(rec, a.DatabaseSpecific.Severity)
			out = append(out, Match{
				Ecosystem: eco, Name: a.Package.Name, Version: v, VulnID: rec.ID, Aliases: rec.Aliases,
				Summary: summary(rec), Severity: sev, Fixed: fixed, Published: rec.Published,
			})
		}
	}
	return out
}

// ecosystemBase drops ecosystem suffixes ("Debian:11" → "Debian").
func ecosystemBase(e string) string {
	b, _, _ := strings.Cut(e, ":")
	return b
}

// inRanges applies OSV's range algorithm to ECOSYSTEM and SEMVER ranges.
func inRanges(eco, version string, ranges []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
		Limit        string `json:"limit"`
	} `json:"events"`
},
) (bool, string) {
	v, err := semantic.Parse(version, eco)
	if err != nil {
		return false, ""
	}
	cmp := func(other string) int {
		c, err := v.CompareStr(other)
		if err != nil {
			return 0
		}
		return c
	}
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
			continue
		}
		affected, fixed := false, ""
		// Events are applied in version order; "0" means "from the start".
		type ev struct{ kind, val string }
		var evs []ev
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				evs = append(evs, ev{"introduced", e.Introduced})
			case e.Fixed != "":
				evs = append(evs, ev{"fixed", e.Fixed})
			case e.LastAffected != "":
				evs = append(evs, ev{"last_affected", e.LastAffected})
			}
		}
		// OSV does not require events to be ordered.
		sort.SliceStable(evs, func(i, j int) bool { return lessVersion(eco, evs[i].val, evs[j].val) })
		for _, e := range evs {
			switch e.kind {
			case "introduced":
				if e.val == "0" || cmp(e.val) >= 0 {
					affected = true
				}
			case "fixed":
				if cmp(e.val) >= 0 {
					affected = false
				} else if affected && fixed == "" {
					fixed = e.val
				}
			case "last_affected":
				if cmp(e.val) > 0 {
					affected = false
				}
			}
		}
		if affected {
			return true, fixed
		}
	}
	return false, ""
}

func lessVersion(eco, a, b string) bool {
	switch {
	case a == "0":
		return b != "0"
	case b == "0":
		return false
	}
	pa, err := semantic.Parse(a, eco)
	if err != nil {
		return a < b
	}
	c, err := pa.CompareStr(b)
	if err != nil {
		return a < b
	}
	return c < 0
}

func summary(r *Record) string {
	s := r.Summary
	if s == "" {
		s, _, _ = strings.Cut(strings.TrimSpace(r.Details), "\n")
	}
	if len(s) > 300 {
		s = s[:297] + "..."
	}
	return s
}

// severityOf uses the advisory's own rating (GitHub: CRITICAL/HIGH/
// MODERATE/LOW), then a CVSS v3 vector, else medium.
func severityOf(r *Record, affectedSev string) string {
	for _, s := range []string{affectedSev, r.DatabaseSpecific.Severity} {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return "critical"
		case "HIGH":
			return "high"
		case "MODERATE", "MEDIUM":
			return "medium"
		case "LOW":
			return "low"
		}
	}
	for _, s := range r.Severity {
		if s.Type == "CVSS_V3" {
			if score, ok := CVSS3(s.Score); ok {
				switch {
				case score >= 9:
					return "critical"
				case score >= 7:
					return "high"
				case score >= 4:
					return "medium"
				case score > 0:
					return "low"
				}
			}
		}
	}
	return "medium"
}

// CVSS3 computes the base score of a CVSS v3.x vector.
func CVSS3(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	scope := m["S"]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || (scope != "U" && scope != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	score := impact + expl
	if scope == "C" {
		score *= 1.08
	}
	return roundUp(math.Min(score, 10)), true
}

// roundUp is CVSS's "round up to one decimal".
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// SortMatches orders matches worst first.
func SortMatches(ms []Match) {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(ms, func(i, j int) bool {
		if rank[ms[i].Severity] != rank[ms[j].Severity] {
			return rank[ms[i].Severity] > rank[ms[j].Severity]
		}
		return ms[i].VulnID+ms[i].Name+ms[i].Version < ms[j].VulnID+ms[j].Name+ms[j].Version
	})
}

// CVE returns the CVE alias of an advisory, if any.
func CVE(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}
