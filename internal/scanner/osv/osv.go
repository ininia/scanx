// Package osv adapts OSV-Scanner (offline mode) as a second opinion for
// dependency vulnerabilities. Licenses are not requested: that mode calls
// the deps.dev API and cannot run offline.
package osv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

const outFile = "osv.json"

// Scanner is the OSV-Scanner adapter.
type Scanner struct{}

func init() { scanner.Register(Scanner{}) }

// ID implements scanner.Scanner.
func (Scanner) ID() string { return "osv-scanner" }

// Name implements scanner.Scanner.
func (Scanner) Name() string { return "OSV-Scanner (dependencies)" }

// Tool implements scanner.Scanner.
func (Scanner) Tool() string { return "osv-scanner" }

// Category implements scanner.Scanner.
func (Scanner) Category() finding.Category { return finding.CategorySCA }

// Applies implements scanner.Scanner: only when manifests or lock files exist.
func (Scanner) Applies(d *detect.Result, _ scanner.Settings) bool { return len(d.Lockfiles) > 0 }

// Timeout implements scanner.Scanner.
func (Scanner) Timeout(scanner.Settings) time.Duration { return 10 * time.Minute }

// VersionCmd implements scanner.VersionReporter.
func (Scanner) VersionCmd() scanner.Cmd {
	return scanner.Cmd{Path: "osv-scanner", Args: []string{"--version"}}
}

// Command implements scanner.Scanner. Exit code 1 means "vulnerabilities
// found" and 128 "no packages found"; both are successful runs.
func (Scanner) Command(env scanner.Env, _ scanner.Settings) scanner.Cmd {
	return scanner.Cmd{
		Path: "osv-scanner",
		Args: []string{
			"scan", "source", "-r", "--offline",
			"--format", "json", "--output-file", filepath.Join(env.OutDir, outFile),
			env.SourceDir,
		},
		Env:         []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + filepath.Join(env.DBDir, "osv")},
		OKExitCodes: []int{0, 1, 128},
	}
}

type output struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
			Vulnerabilities []vuln `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

type vuln struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	DatabaseSpecific struct {
		CWEIDs   []string `json:"cwe_ids"`
		Severity string   `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// Parse implements scanner.Scanner. When the output file is missing because
// no packages were found (exit 128), the result is empty.
func (Scanner) Parse(env scanner.Env) ([]finding.Finding, error) {
	data, err := os.ReadFile(filepath.Join(env.OutDir, outFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func parse(data []byte) ([]finding.Finding, error) {
	var o output
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("osv json: %w", err)
	}
	var out []finding.Finding
	for _, res := range o.Results {
		for _, p := range res.Packages {
			byID := map[string]vuln{}
			for _, v := range p.Vulnerabilities {
				byID[v.ID] = v
			}
			for _, g := range p.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				v := byID[g.IDs[0]]
				ids := uniq(append(append([]string{}, g.IDs...), g.Aliases...))
				sev := finding.Info
				if score, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil && score > 0 {
					sev = finding.FromCVSS(score)
				} else if s, ok := finding.FromVendor(v.DatabaseSpecific.Severity); ok {
					sev = s
				}
				fixed := fixedVersion(v, p.Package.Version)
				primary := preferredID(ids)
				title := primary + " in " + p.Package.Name + " " + p.Package.Version
				if v.Summary != "" {
					title += ": " + v.Summary
				}
				rem := ""
				if fixed != "" {
					rem = "Upgrade " + p.Package.Name + " to " + fixed + " or later."
				}
				var refs []string
				for _, r := range v.References {
					if len(refs) < 5 {
						refs = append(refs, r.URL)
					}
				}
				out = append(out, finding.Finding{
					Tool: "osv-scanner", RuleID: g.IDs[0], Category: finding.CategorySCA, Severity: sev,
					Title: title, Description: v.Details, Remediation: rem,
					CVE: ids, CWE: finding.NormalizeCWEs(v.DatabaseSpecific.CWEIDs...),
					Package: &finding.PackageRef{
						Name: p.Package.Name, Version: p.Package.Version, FixedVersion: fixed,
						Ecosystem: strings.ToLower(p.Package.Ecosystem),
					},
					File: res.Source.Path, References: refs,
				})
			}
		}
	}
	return out, nil
}

// preferredID picks a CVE id when available (most widely recognized).
func preferredID(ids []string) string {
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return ids[0]
}

// fixedVersion returns the lowest "fixed" event greater than installed.
func fixedVersion(v vuln, installed string) string {
	best := ""
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				f, ok := ev["fixed"]
				if !ok || compareVersions(f, installed) <= 0 {
					continue
				}
				if best == "" || compareVersions(f, best) < 0 {
					best = f
				}
			}
		}
	}
	return best
}

var numRe = regexp.MustCompile(`\d+`)

// compareVersions compares dotted numeric versions (good enough to pick
// fixed versions; pre-release tags are ignored).
func compareVersions(a, b string) int {
	pa, pb := numRe.FindAllString(a, -1), numRe.FindAllString(b, -1)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
