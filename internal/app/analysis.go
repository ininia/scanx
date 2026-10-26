package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/forecast"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/prune"
)

type analysisTree struct {
	dir    string // "" = tools read the checkout itself
	ownDir bool   // dir was created here and is removed afterwards
	stats  *prune.Stats
}

// buildAnalysisTree prunes the checkout for code analysis. It prefers a
// sibling directory of the checkout (same file system: hard links) and
// falls back to the temp dir; on any problem the tools read the checkout.
func buildAnalysisTree(o ScanOptions, s scanner.Settings, tmp string, stderr io.Writer) (int64, analysisTree) {
	start := time.Now()
	opt := prune.Options{
		Excludes: scanner.AllExcludes(s), MaxFileBytes: int64(o.MaxFileMB) << 20,
		SkipMinified: o.SkipMinified, SkipBundles: o.SkipBundles,
	}
	full := checkoutSize(o.Path)
	for _, dst := range []string{filepath.Join(filepath.Dir(o.Path), "analysis"), filepath.Join(tmp, "analysis")} {
		if _, err := os.Stat(dst); err == nil {
			continue // never reuse or delete a directory we did not create
		}
		st, err := prune.Build(o.Path, dst, opt)
		if err != nil {
			_ = os.RemoveAll(dst)
			continue
		}
		fmt.Fprintf(stderr, "[%s] code analysis covers %d files (%s); left out %d files (%s): %s [%s]\n",
			time.Now().Format("15:04:05"), st.Files, mb(st.Bytes), st.SkippedFiles, mb(st.SkippedBytes),
			skippedSummary(st.Skipped, 6), time.Since(start).Round(100*time.Millisecond))
		return full, analysisTree{dir: dst, ownDir: true, stats: st}
	}
	fmt.Fprintf(stderr, "[%s] could not build the analysis tree; code analysis reads the whole checkout\n", time.Now().Format("15:04:05"))
	return full, analysisTree{stats: &prune.Stats{Files: 0, Bytes: full}}
}

func skippedSummary(ds []prune.Dir, n int) string {
	var parts []string
	for i, d := range ds {
		if i == n {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s (%s)", d.Path, mb(d.Bytes), d.Reason))
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// checkoutSize is the size of the tree without .git.
func checkoutSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

func mb(b int64) string {
	if b < 1<<20 {
		return fmt.Sprintf("%d KB", b>>10)
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
}

// orderScanners runs the quick tools first (see forecast.Order).
func orderScanners(sel []scanner.Scanner, analysisBytes, fullBytes int64) []scanner.Scanner {
	byID := map[string]scanner.Scanner{}
	ids := make([]string, 0, len(sel))
	for _, sc := range sel {
		byID[sc.ID()] = sc
		ids = append(ids, sc.ID())
	}
	out := make([]scanner.Scanner, 0, len(sel))
	for _, id := range forecast.Order(ids, analysisBytes, fullBytes) {
		out = append(out, byID[id])
	}
	return out
}

// reportForecast prints the expected duration (and a warning when it does
// not fit the time budget) plus the machine-readable stats line.
func reportForecast(stderr io.Writer, o ScanOptions, sel []scanner.Scanner, st *prune.Stats, full int64, par int) {
	ids := make([]string, 0, len(sel))
	for _, sc := range sel {
		ids = append(ids, sc.ID())
	}
	est := forecast.Estimate(forecast.Input{Tools: ids, AnalysisBytes: st.Bytes, FullBytes: full, Parallelism: par})
	now := time.Now().Format("15:04:05")
	fmt.Fprintf(stderr, "[%s] estimated scan time ~%s\n", now, roundMin(est))
	if o.TimeBudget > 0 && est > o.TimeBudget {
		fmt.Fprintf(stderr, "[%s] ⚠ the estimate exceeds the time limit (%s): the slowest scanners may be stopped and the result marked partial. Exclude large folders or switch off slow scanners in the project settings.\n",
			now, roundMin(o.TimeBudget))
	}
	b, err := json.Marshal(forecast.Stats{
		Analysis: st, FullBytes: full, Tools: ids, Parallelism: par,
		EstimateS: int64(est.Seconds()), BudgetS: int64(o.TimeBudget.Seconds()),
	})
	if err == nil {
		fmt.Fprintf(stderr, "%s%s\n", forecast.StatsPrefix, b)
	}
}

func roundMin(d time.Duration) string {
	return fmt.Sprintf("%d min", max(int(d.Round(time.Minute).Minutes()), 1))
}
