// Package forecast predicts how long a repository scan takes, so that a
// scan which cannot finish within its time limit is flagged before (and
// when) it starts. The model is per tool: a start-up cost plus a cost per
// MB of the tree the tool reads (the pruned analysis tree for code
// analysis, the full checkout for secret and dependency scanners). The
// figures were measured on one vCPU with one scanner at a time; a project's
// own history corrects them (see Correct).
package forecast

import (
	"sort"
	"time"

	"github.com/ininia/scanx/internal/scanner/prune"
)

// StatsPrefix marks the scanner's machine-readable line with the analysis
// tree and its forecast; the worker keeps it for the next forecast.
const StatsPrefix = "SCANX_STATS "

// Stats is the payload of the StatsPrefix line; the worker adds the
// outcome and stores it as projects.scan_stats.
type Stats struct {
	Analysis    *prune.Stats `json:"analysis"`
	FullBytes   int64        `json:"full_bytes"`
	Tools       []string     `json:"tools"`
	Parallelism int          `json:"parallelism"`
	EstimateS   int64        `json:"estimate_s"`
	BudgetS     int64        `json:"budget_s,omitempty"`
	// Set by the worker when the scan ended.
	ActualS  int64     `json:"actual_s,omitempty"`
	Complete bool      `json:"complete,omitempty"` // every scanner ran to the end
	Outcome  string    `json:"outcome,omitempty"`  // completed | partial | timeout | failed
	At       time.Time `json:"at"`
}

type cost struct {
	fixed time.Duration // start-up: rule loading, runtime start
	perMB time.Duration // per MB of the tree the tool reads
	full  bool          // reads the full checkout instead of the analysis tree
}

// Measured on a 12 MB PHP/JS analysis tree in a 310 MB checkout (1 vCPU):
// opengrep 7m50s, Psalm 6m48s, DevSkim 40s, Lizard 10s, Gitleaks 41s +
// 1m33s (history), Trivy 45s, Checkov 16s.
var costs = map[string]cost{
	"opengrep":     {fixed: 40 * time.Second, perMB: 37 * time.Second},
	"psalm":        {fixed: 20 * time.Second, perMB: 33 * time.Second},
	"devskim":      {fixed: 10 * time.Second, perMB: 2500 * time.Millisecond},
	"lizard":       {fixed: 3 * time.Second, perMB: 600 * time.Millisecond},
	"gosec":        {fixed: 15 * time.Second, perMB: 20 * time.Second},
	"bandit":       {fixed: 2 * time.Second, perMB: 4 * time.Second},
	"ruff":         {fixed: time.Second, perMB: time.Second},
	"shellcheck":   {fixed: time.Second, perMB: 2 * time.Second},
	"spectral":     {fixed: 3 * time.Second},
	"hadolint":     {fixed: 2 * time.Second},
	"actionlint":   {fixed: time.Second},
	"zizmor":       {fixed: time.Second},
	"kube-linter":  {fixed: 2 * time.Second},
	"checkov":      {fixed: 15 * time.Second, perMB: 5 * time.Millisecond, full: true},
	"gitleaks-dir": {fixed: 5 * time.Second, perMB: 120 * time.Millisecond, full: true},
	"gitleaks-git": {fixed: 10 * time.Second, perMB: 270 * time.Millisecond, full: true},
	"trivy-fs":     {fixed: 30 * time.Second, perMB: 50 * time.Millisecond, full: true},
	"osv-scanner":  {fixed: 3 * time.Second, perMB: 5 * time.Millisecond, full: true},
	"syft":         {fixed: 4 * time.Second, perMB: 5 * time.Millisecond, full: true},
}

// unknownTool is used for scanners the model does not know yet.
var unknownTool = cost{fixed: 15 * time.Second, perMB: 5 * time.Second}

// Overhead covers detection, the analysis tree and writing the reports.
const Overhead = time.Minute

// Input describes a scan.
type Input struct {
	Tools         []string // scanner IDs that will run
	AnalysisBytes int64    // pruned tree (code analysis)
	FullBytes     int64    // full checkout without .git
	Parallelism   int
}

// Tool predicts one scanner's run time.
func Tool(id string, analysisBytes, fullBytes int64) time.Duration {
	c, ok := costs[id]
	if !ok {
		c = unknownTool
	}
	b := analysisBytes
	if c.full {
		b = fullBytes
	}
	return c.fixed + time.Duration(float64(c.perMB)*float64(b)/(1<<20))
}

// Estimate predicts the total scan time.
func Estimate(in Input) time.Duration {
	var tools []time.Duration
	for _, id := range in.Tools {
		tools = append(tools, Tool(id, in.AnalysisBytes, in.FullBytes))
	}
	return Overhead + schedule(tools, max(in.Parallelism, 1))
}

// schedule is the makespan of running the durations on n slots in order
// (longest first, the way a busy queue behaves on average).
func schedule(ds []time.Duration, n int) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] > ds[j] })
	slots := make([]time.Duration, n)
	for _, d := range ds {
		k := 0
		for i := range slots {
			if slots[i] < slots[k] {
				k = i
			}
		}
		slots[k] += d
	}
	var end time.Duration
	for _, s := range slots {
		end = max(end, s)
	}
	return end
}

// Correct scales a model estimate by how far the model was off on the
// project's previous complete scan (clamped, so one odd run cannot skew
// the forecast too much).
func Correct(est, lastEstimate, lastActual time.Duration) time.Duration {
	if lastEstimate <= 0 || lastActual <= 0 {
		return est
	}
	f := float64(lastActual) / float64(lastEstimate)
	f = min(max(f, 0.4), 3)
	return time.Duration(float64(est) * f)
}

// Order sorts scanner IDs cheapest first, so that when a scan runs out of
// time the quick, high-value tools (secrets, dependencies) have finished.
func Order(ids []string, analysisBytes, fullBytes int64) []string {
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool {
		return Tool(out[i], analysisBytes, fullBytes) < Tool(out[j], analysisBytes, fullBytes)
	})
	return out
}
