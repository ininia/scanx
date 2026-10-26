package ui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/forecast"
	"github.com/ininia/scanx/internal/service"
)

// MB formats a byte count ("12.4 MB", "830 KB").
func MB(b int64) string {
	if b < 1<<20 {
		return fmt.Sprintf("%d KB", max(b>>10, 1))
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
}

// Mins is a duration in whole minutes (at least 1).
func Mins(d time.Duration) int { return max(int(d.Round(time.Minute).Minutes()), 1) }

// Runs reports whether a scanner is switched on for the project.
func (v *ProjectView) Runs(id string) bool { return !slices.Contains(v.Scope.Disabled, id) }

// ToolEstimate is the expected run time of one scanner, from the last
// scan's tree sizes (0 when unknown).
func (v *ProjectView) ToolEstimate(id string) time.Duration {
	if v.Forecast == nil || v.Forecast.Last == nil || v.Forecast.Last.Analysis == nil {
		return 0
	}
	return forecast.Tool(id, v.Forecast.Last.Analysis.Bytes, v.Forecast.Last.FullBytes)
}

// ExcludeText is the exclude list for the textarea.
func (v *ProjectView) ExcludeText() string { return strings.Join(v.Scope.Exclude, "\n") }

// ScannerGroups are the scanners by category, in a fixed order.
func ScannerGroups() [][]service.ScannerInfo {
	order := []string{"sast", "quality", "secret", "sca", "license", "iac", "container"}
	by := map[string][]service.ScannerInfo{}
	for _, s := range service.Scanners() {
		by[s.Category] = append(by[s.Category], s)
	}
	var out [][]service.ScannerInfo
	for _, c := range order {
		if len(by[c]) > 0 {
			out = append(out, by[c])
			delete(by, c)
		}
	}
	for _, g := range by {
		out = append(out, g)
	}
	return out
}
