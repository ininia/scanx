package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ininia/scanx/internal/forecast"
	"github.com/ininia/scanx/internal/report"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/store/db"
)

// scanLimit is the time the scan container of p may run: the instance
// limit, but at least the code-analysis limit plus time for the others.
func (w *Worker) scanLimit(p *db.Project) time.Duration {
	sast := time.Duration(p.SastTimeoutMinutes) * time.Minute
	if sast <= 0 {
		sast = scanner.DefaultSASTTimeout
	}
	return max(w.cfg.ScanTimeout, sast+15*time.Minute)
}

// saveScanStats keeps what the scanner reported about a full scan (tree
// sizes, forecast) with its outcome, for the next forecast. Incremental
// scans see only the changed files and are not representative.
func (w *Worker) saveScanStats(ctx context.Context, p *db.Project, lg *scanLog, rep *report.Report, scanErr error) {
	lg.mu.Lock()
	raw, start := lg.stats, lg.scanStart
	lg.mu.Unlock()
	if len(raw) == 0 || start.IsZero() {
		return
	}
	var st forecast.Stats
	if json.Unmarshal(raw, &st) != nil || st.Analysis == nil {
		return
	}
	var sf *scanFailure
	switch {
	case rep != nil && rep.Partial:
		st.Outcome = "partial"
	case rep != nil:
		st.Outcome, st.Complete = "completed", true
	case errors.As(scanErr, &sf) && sf.code == "scan_timeout":
		st.Outcome = "timeout"
	default:
		st.Outcome = "failed"
	}
	st.ActualS = int64(time.Since(start).Seconds())
	st.At = time.Now().UTC()
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = w.db.Tx(sctx, superadmin, func(q *db.Queries) error {
		return q.SetProjectScanStats(sctx, db.SetProjectScanStatsParams{ID: p.ID, ScanStats: b})
	})
}
