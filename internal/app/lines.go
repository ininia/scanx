package app

import (
	"encoding/json"
	"os"

	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/gitfetch"
)

// scopeToLines keeps only the findings on lines a push added or changed
// (incremental scans: older issues elsewhere in a touched file belong to
// full scans). Findings without a line (e.g. a vulnerable dependency in a
// lock file) are kept; the worker drops those it already knows. It returns
// the fingerprints of every finding in the touched files, so the worker
// does not mark issues outside the changed lines as fixed, and false when
// the line list is missing (whole files are reported then).
func scopeToLines(listFile string, res *engine.Result) ([]string, bool) {
	if listFile == "" {
		return nil, false
	}
	raw, err := os.ReadFile(listFile) //nolint:gosec // path chosen by the worker
	if err != nil {
		return nil, false
	}
	var lines map[string][]gitfetch.LineRange
	if json.Unmarshal(raw, &lines) != nil {
		return nil, false
	}
	seen := make([]string, 0, len(res.Findings))
	kept := res.Findings[:0]
	for _, f := range res.Findings {
		seen = append(seen, f.Fingerprint)
		if onChangedLines(f, lines) {
			kept = append(kept, f)
		}
	}
	res.Findings = kept
	return seen, true
}

func onChangedLines(f finding.Finding, lines map[string][]gitfetch.LineRange) bool {
	ranges, ok := lines[f.File]
	if !ok || f.StartLine <= 0 {
		return true // not a line-level finding, or a file the diff did not list
	}
	end := max(f.EndLine, f.StartLine)
	for _, r := range ranges {
		if f.StartLine <= r[1] && end >= r[0] {
			return true
		}
	}
	return false
}
