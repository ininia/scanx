// Package engine runs the selected scanners against a source tree, in
// parallel and with per-tool timeouts, and collects normalized findings.
// A failing tool never fails the scan; the result is marked partial instead.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/scanner"
)

// Tool run statuses.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusTimeout = "timeout"
)

// ToolRun records one scanner execution (scan_tools row).
type ToolRun struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Findings   int    `json:"findings"`
	Error      string `json:"error,omitempty"`
	LogExcerpt string `json:"log_excerpt,omitempty"`
}

// Result is the outcome of a scan.
type Result struct {
	Detection *detect.Result    `json:"detected"`
	Tools     []ToolRun         `json:"tools"`
	Findings  []finding.Finding `json:"-"`
	Partial   bool              `json:"partial"`
}

// Runner executes a command. ExecRunner is the production implementation;
// tests substitute fakes.
type Runner interface {
	Run(ctx context.Context, c scanner.Cmd, dir string) (exitCode int, output []byte, err error)
}

// Options configures Run.
type Options struct {
	Parallelism   int
	StoreSnippets bool
	Logger        *slog.Logger
	// Progress receives one human-readable line per event (tool started /
	// finished / still running). The worker shows it live on the scan page.
	Progress io.Writer
	// Heartbeat is how often "still running" lines are written (default 1m).
	Heartbeat time.Duration
}

// progress writes timestamped progress lines; safe for concurrent use.
type progress struct {
	mu sync.Mutex
	w  io.Writer
}

func (p *progress) printf(format string, a ...any) {
	if p == nil || p.w == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%s] "+format+"\n", append([]any{time.Now().Format("15:04:05")}, a...)...)
}

// Run executes scanners and returns the combined, normalized findings.
func Run(ctx context.Context, r Runner, env scanner.Env, s scanner.Settings, d *detect.Result,
	scanners []scanner.Scanner, opt Options,
) *Result {
	if opt.Parallelism < 1 {
		opt.Parallelism = 1
	}
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	res := &Result{Detection: d, Tools: make([]ToolRun, len(scanners))}
	perTool := make([][]finding.Finding, len(scanners))

	pr := &progress{w: opt.Progress}
	if opt.Heartbeat <= 0 {
		opt.Heartbeat = time.Minute
	}
	names := make([]string, 0, len(scanners))
	for _, sc := range scanners {
		names = append(names, sc.Name())
	}
	pr.printf("%d scanners selected: %s", len(scanners), strings.Join(names, ", "))
	sem := make(chan struct{}, opt.Parallelism)
	var wg sync.WaitGroup
	for i, sc := range scanners {
		wg.Add(1)
		go func(i int, sc scanner.Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pr.printf("▶ %s started (limit %s)", sc.Name(), sc.Timeout(s))
			stop := make(chan struct{})
			go func(start time.Time) {
				t := time.NewTicker(opt.Heartbeat)
				defer t.Stop()
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						pr.printf("… %s still running (%s)", sc.Name(), time.Since(start).Round(time.Second))
					}
				}
			}(time.Now())
			run, fs := runOne(ctx, r, env, s, sc)
			close(stop)
			mark := "✔"
			if run.Status != StatusOK {
				mark = "✖"
			}
			detail := fmt.Sprintf("%d findings", run.Findings)
			if run.Error != "" {
				detail = run.Error
			}
			pr.printf("%s %s %s in %s: %s", mark, sc.Name(), run.Status, (time.Duration(run.DurationMS) * time.Millisecond).Round(time.Second), detail)
			res.Tools[i] = run
			perTool[i] = fs
			log.InfoContext(ctx, "scanner finished", "scanner", run.ID, "status", run.Status,
				"findings", run.Findings, "duration_ms", run.DurationMS)
		}(i, sc)
	}
	wg.Wait()

	for i, t := range res.Tools {
		if t.Status != StatusOK {
			res.Partial = true
		}
		res.Findings = append(res.Findings, perTool[i]...)
	}
	for _, sc := range scanners {
		if pp, ok := sc.(scanner.PostProcessor); ok {
			res.Findings = pp.PostProcess(res.Findings)
		}
	}
	finding.Normalize(res.Findings, finding.NormalizeOptions{SourceRoot: env.SourceDir, StoreSnippets: opt.StoreSnippets})
	res.Findings = FilterExcluded(res.Findings, s.Exclude)
	return res
}

// FilterExcluded drops findings whose file matches an exclude pattern. Not
// every tool supports excludes, so the engine enforces them uniformly.
// Patterns without "/" match any path segment ("testdata", "*.min.js");
// patterns with "/" match the path or a leading directory ("docs/examples").
func FilterExcluded(fs []finding.Finding, patterns []string) []finding.Finding {
	if len(patterns) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if !Excluded(f.File, patterns) {
			out = append(out, f)
		}
	}
	return out
}

// Excluded reports whether a repository-relative path matches any pattern.
func Excluded(p string, patterns []string) bool {
	if p == "" {
		return false
	}
	segs := strings.Split(p, "/")
	for _, pat := range patterns {
		pat = strings.Trim(strings.TrimPrefix(pat, "./"), "/")
		if pat == "" {
			continue
		}
		if !strings.Contains(pat, "/") {
			for _, seg := range segs {
				if ok, _ := path.Match(pat, seg); ok {
					return true
				}
			}
			continue
		}
		if p == pat || strings.HasPrefix(p, pat+"/") {
			return true
		}
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
	}
	return false
}

func runOne(ctx context.Context, r Runner, env scanner.Env, s scanner.Settings, sc scanner.Scanner) (ToolRun, []finding.Finding) {
	run := ToolRun{ID: sc.ID(), Name: sc.Name()}
	if vr, ok := sc.(scanner.VersionReporter); ok {
		vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if _, out, err := r.Run(vctx, vr.VersionCmd(), env.TmpDir); err == nil {
			run.Version = parseVersion(out)
		}
		cancel()
	}
	tctx, cancel := context.WithTimeout(ctx, sc.Timeout(s))
	defer cancel()
	start := time.Now()
	code, out, err := r.Run(tctx, sc.Command(env, s), env.TmpDir)
	run.DurationMS = time.Since(start).Milliseconds()
	run.ExitCode = code
	run.LogExcerpt = excerpt(out)
	cmd := sc.Command(env, s)
	switch {
	case errors.Is(tctx.Err(), context.DeadlineExceeded):
		run.Status, run.Error = StatusTimeout, fmt.Sprintf("timed out after %s", sc.Timeout(s))
		return run, nil
	case err != nil && !isExitError(err):
		run.Status, run.Error = StatusFailed, err.Error()
		return run, nil
	case !okExit(cmd.OKExitCodes, code):
		run.Status, run.Error = StatusFailed, fmt.Sprintf("exit code %d", code)
		return run, nil
	}
	fs, err := sc.Parse(env)
	if err != nil {
		run.Status, run.Error = StatusFailed, "parse output: "+err.Error()
		return run, nil
	}
	run.Status, run.Findings = StatusOK, len(fs)
	return run, fs
}

func okExit(ok []int, code int) bool {
	if len(ok) == 0 {
		return code == 0
	}
	for _, c := range ok {
		if c == code {
			return true
		}
	}
	return false
}

func isExitError(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee)
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.]+)?)`)

func parseVersion(out []byte) string {
	if m := versionRe.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// excerpt keeps the last 4 KiB of tool output, with anything secret-looking
// masked: logs are stored and shown in the UI.
func excerpt(out []byte) string {
	const max = 4096
	out = bytes.TrimSpace(out)
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return finding.MaskText(strings.ToValidUTF8(string(out), "?"))
}

// ExecRunner runs commands as child processes without a shell.
type ExecRunner struct {
	// BaseEnv is the environment every tool gets (PATH, HOME, LANG...).
	BaseEnv []string
}

// Run implements Runner.
func (e ExecRunner) Run(ctx context.Context, c scanner.Cmd, dir string) (int, []byte, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...) //nolint:gosec // fixed tool binaries, argument arrays, no shell
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, e.BaseEnv...), c.Env...)
	var buf limitedBuffer
	buf.max = 256 << 10
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if c.StdoutFile != "" {
		f, err := os.Create(c.StdoutFile)
		if err != nil {
			return -1, nil, err
		}
		defer func() { _ = f.Close() }()
		cmd.Stdout = f
	}
	cmd.WaitDelay = 5 * time.Second
	configureProcessGroup(cmd)
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return code, buf.Bytes(), err
}

// DefaultBaseEnv builds the minimal environment for tools.
func DefaultBaseEnv(env scanner.Env) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=" + env.TmpDir, // writable; read-only caches are passed per tool
		"TMPDIR=" + env.TmpDir,
		"XDG_CACHE_HOME=" + env.TmpDir + "/cache",
		"LANG=C.UTF-8", "LC_ALL=C.UTF-8",
		// Never let a tool phone home.
		"DO_NOT_TRACK=1",
	}
}

// limitedBuffer keeps only the last max bytes written.
type limitedBuffer struct {
	mu  sync.Mutex
	b   []byte
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	if len(l.b) > l.max {
		l.b = l.b[len(l.b)-l.max:]
	}
	return len(p), nil
}

func (l *limitedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b...)
}
