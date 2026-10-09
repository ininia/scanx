package worker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/store/db"
)

const (
	maxLogBytes   = 64 << 10
	maxToolLines  = 400
	logPollPeriod = 5 * time.Second
)

// scanLog is the live progress log shown on the scan page: the worker's own
// steps plus the progress lines the scan container prints.
type scanLog struct {
	w     *Worker
	id    uuid.UUID
	mu    sync.Mutex
	steps []string
	tool  string
	last  string
}

func newScanLog(w *Worker, id uuid.UUID) *scanLog { return &scanLog{w: w, id: id} }

// add records a worker step and saves the log.
func (l *scanLog) add(ctx context.Context, format string, a ...any) {
	l.mu.Lock()
	l.steps = append(l.steps, "["+time.Now().Format("15:04:05")+"] "+fmt.Sprintf(format, a...))
	l.mu.Unlock()
	l.flush(ctx)
}

// setTool replaces the scan container's part of the log with the progress
// lines found in its stderr.
func (l *scanLog) setTool(ctx context.Context, stderr []byte) {
	var keep []string
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "scanX ") {
			keep = append(keep, line)
		}
	}
	if len(keep) > maxToolLines {
		keep = keep[len(keep)-maxToolLines:]
	}
	l.mu.Lock()
	l.tool = strings.Join(keep, "\n")
	l.mu.Unlock()
	l.flush(ctx)
}

func (l *scanLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	parts := append([]string{}, l.steps...)
	if l.tool != "" {
		parts = append(parts, l.tool)
	}
	s := strings.Join(parts, "\n")
	if len(s) > maxLogBytes {
		s = "…\n" + s[len(s)-maxLogBytes:]
	}
	return s
}

func (l *scanLog) flush(ctx context.Context) {
	s := l.text()
	l.mu.Lock()
	same := s == l.last
	l.last = s
	l.mu.Unlock()
	if same {
		return
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = l.w.db.Tx(fctx, superadmin, func(q *db.Queries) error {
		return q.SetScanLog(fctx, db.SetScanLogParams{ID: l.id, Log: s})
	})
}
