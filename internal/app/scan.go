package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/detect"
	"github.com/ininia/scanx/internal/engine"
	"github.com/ininia/scanx/internal/finding"
	"github.com/ininia/scanx/internal/report"
	"github.com/ininia/scanx/internal/scanner"
	"github.com/ininia/scanx/internal/scanner/syft"
	"github.com/ininia/scanx/internal/version"
)

// Scan exit codes (spec §12.1).
const (
	ExitPass       = 0
	ExitGateFailed = 1
	ExitScanError  = 2
	ExitConfig     = 3
)

// DefaultScannerImage is used by the docker engine.
var DefaultScannerImage = "ghcr.io/ininia/scanx-scanner-all:" + imageTag()

func imageTag() string {
	if version.Version == "dev" || version.Version == "" {
		return "dev"
	}
	return strings.TrimPrefix(version.Version, "v")
}

// ScanOptions are the `scanx scan` flags.
type ScanOptions struct {
	Path        string
	Out         string
	Formats     []string // json, sarif, html
	FailOn      string
	Engine      string // auto | exec | docker
	Image       string
	History     bool
	Profile     string
	Exclude     []string
	NoSnippets  bool
	Parallelism int
	SASTTimeout time.Duration
	// OnlyFiles names a file listing repository-relative paths (one per
	// line); only those files are scanned (incremental scan of a push).
	OnlyFiles string
	Branch    string
	Commit    string
	Repo      string
	// DisplayPath / DisplayOut are the host paths shown to the user when the
	// scan runs inside the scanner container (docker engine).
	DisplayPath string
	DisplayOut  string
}

// RunScan executes a scan and returns the process exit code.
func RunScan(ctx context.Context, o ScanOptions, stdout, stderr io.Writer) int {
	policy, err := report.ParseFailOn(o.FailOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitConfig
	}
	for _, f := range o.Formats {
		switch f {
		case "json", "sarif", "html":
		default:
			fmt.Fprintf(stderr, "unknown --format %q (json, sarif, html)\n", f)
			return ExitConfig
		}
	}
	switch o.Profile {
	case "fast", "default", "full":
	default:
		fmt.Fprintln(stderr, "--profile must be fast, default or full")
		return ExitConfig
	}
	src, err := filepath.Abs(o.Path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitConfig
	}
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "--path %s is not a directory\n", o.Path)
		return ExitConfig
	}
	out, err := filepath.Abs(o.Out)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitConfig
	}
	o.Path, o.Out = src, out

	eng := o.Engine
	if eng == "auto" {
		eng = "docker"
		if toolsAvailable() {
			eng = "exec"
		}
	}
	switch eng {
	case "exec":
		return runExecScan(ctx, o, policy, stdout, stderr)
	case "docker":
		return runDockerScan(ctx, o, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "--engine must be auto, exec or docker")
		return ExitConfig
	}
}

// toolsAvailable reports whether the scanner image layout is present (we are
// running inside the all-in-one image or an equivalent installation).
func toolsAvailable() bool {
	if os.Getenv("SCANX_RULES_DIR") == "" {
		return false
	}
	for _, t := range []string{"gitleaks", "opengrep", "trivy", "osv-scanner", "syft"} {
		if _, err := exec.LookPath(t); err != nil {
			return false
		}
	}
	return true
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runExecScan(ctx context.Context, o ScanOptions, policy report.Policy, stdout, stderr io.Writer) int {
	started := time.Now()
	rawDir := filepath.Join(o.Out, "raw")
	if err := os.MkdirAll(rawDir, 0o750); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitConfig
	}
	tmp, err := os.MkdirTemp("", "scanx-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitScanError
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	if o.OnlyFiles != "" {
		scoped, n, err := scopeTree(o.Path, o.OnlyFiles, tmp)
		if err != nil {
			fmt.Fprintln(stderr, "--only-files:", err)
			return ExitConfig
		}
		fmt.Fprintf(stderr, "[%s] incremental scan: %d changed files\n", time.Now().Format("15:04:05"), n)
		o.Path, o.History = scoped, false
	}

	env := scanner.Env{
		SourceDir: o.Path,
		OutDir:    rawDir,
		RulesDir:  envOr("SCANX_RULES_DIR", "/opt/scanx/rules"),
		DBDir:     envOr("SCANX_DB_DIR", "/opt/scanx/db"),
		ConfigDir: envOr("SCANX_CONFIG_DIR", "/opt/scanx/config"),
		ToolHome:  envOr("SCANX_TOOL_HOME", tmp), // read-only caches baked into the image
		TmpDir:    tmp,                           // writable; also HOME for tools
	}
	settings := scanner.Settings{Profile: o.Profile, History: o.History, Exclude: o.Exclude, SASTTimeout: o.SASTTimeout}
	d, err := detect.Scan(o.Path)
	if err != nil {
		fmt.Fprintln(stderr, "detect:", err)
		return ExitScanError
	}
	for l := range d.Languages {
		settings.Languages = append(settings.Languages, l)
	}
	settings.Languages = append(settings.Languages, d.IaC...)
	sort.Strings(settings.Languages)
	selected := scanner.Select(d, settings)
	par := o.Parallelism
	if par < 1 {
		par = 3
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	fmt.Fprintf(stderr, "scanX %s: scanning %s with %d scanners…\n", version.Version, firstNonEmpty(o.DisplayPath, o.Path), len(selected))
	res := engine.Run(ctx, engine.ExecRunner{BaseEnv: engine.DefaultBaseEnv(env)}, env, settings, d, selected,
		engine.Options{Parallelism: par, StoreSnippets: !o.NoSnippets, Logger: log, Progress: stderr})
	fmt.Fprintf(stderr, "[%s] merging findings and writing reports\n", time.Now().Format("15:04:05"))

	target := report.Target{Path: firstNonEmpty(o.DisplayPath, o.Path), Repo: o.Repo, Branch: o.Branch, Commit: o.Commit}
	rep := report.Build(res, target, started, time.Now(), policy)
	if err := writeReports(rep, o, rawDir); err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return ExitScanError
	}
	printSummary(stdout, rep, o)

	allFailed := len(res.Tools) > 0
	for _, t := range res.Tools {
		if t.Status == engine.StatusOK {
			allFailed = false
		}
	}
	switch {
	case allFailed:
		return ExitScanError
	case rep.Gate.Result == "fail":
		return ExitGateFailed
	default:
		return ExitPass
	}
}

func writeReports(rep *report.Report, o ScanOptions, rawDir string) error {
	write := func(name string, fn func(io.Writer) error) error {
		f, err := os.Create(filepath.Join(o.Out, name)) //nolint:gosec // operator-chosen output dir
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	for _, format := range o.Formats {
		var err error
		switch format {
		case "json":
			err = write("scanx.json", rep.WriteJSON)
		case "sarif":
			err = write("scanx.sarif", rep.WriteSARIF)
		case "html":
			err = write("scanx.html", rep.WriteHTML)
		}
		if err != nil {
			return err
		}
	}
	// Keep the SBOM next to the reports.
	if data, err := os.ReadFile(filepath.Join(rawDir, syft.SBOMFile)); err == nil { //nolint:gosec // our own output
		return os.WriteFile(filepath.Join(o.Out, syft.SBOMFile), data, 0o644) //nolint:gosec // SBOM is not secret
	}
	return nil
}

func printSummary(w io.Writer, r *report.Report, o ScanOptions) {
	s := r.Summary
	fmt.Fprintf(w, "\nscanX results for %s\n", r.Target.Path)
	fmt.Fprintf(w, "  critical %d · high %d · medium %d · low %d · info %d   (score %d/100, grade %s)\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info, r.Score, r.Grade)
	for _, t := range r.Tools {
		mark := "✔"
		if t.Status != engine.StatusOK {
			mark = "✖"
		}
		fmt.Fprintf(w, "  %s %-38s %-8s %3d findings %6.1fs\n", mark, t.Name, t.Status, t.Findings, float64(t.DurationMS)/1000)
	}
	shown := 0
	for _, is := range r.Issues {
		if is.Severity < finding.Medium || shown >= 10 {
			continue
		}
		loc := is.File
		if is.StartLine > 0 {
			loc += ":" + strconv.Itoa(is.StartLine)
		}
		if shown == 0 {
			fmt.Fprintln(w, "\n  Top findings:")
		}
		fmt.Fprintf(w, "  [%-8s] %s  %s\n", strings.ToUpper(is.Severity.String()), trim(is.Title, 80), loc)
		shown++
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "\n  ⚠ %s\n", warn)
	}
	verdict := "PASSED"
	if r.Gate.Result == "fail" {
		verdict = "FAILED (" + strings.Join(r.Gate.Reasons, ", ") + ")"
	}
	fmt.Fprintf(w, "\n  Quality gate [%s]: %s\n  Reports: %s\n", r.Gate.Policy, verdict, firstNonEmpty(o.DisplayOut, o.Out))
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func trim(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// runDockerScan runs the all-in-one image with sandbox hardening and the
// source mounted read-only; the image runs the exec engine (ADR-006).
func runDockerScan(ctx context.Context, o ScanOptions, stdout, stderr io.Writer) int {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(stderr, "docker not found: install Docker or run inside the scanX scanner image (--engine exec)")
		return ExitConfig
	}
	if err := os.MkdirAll(o.Out, 0o750); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitConfig
	}
	image := o.Image
	if image == "" {
		image = DefaultScannerImage
	}
	args := dockerArgs(o, image)
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // fixed binary, argument array, no shell
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return ExitPass
	case errors.As(err, &ee):
		code := ee.ExitCode()
		if code >= 0 && code <= 3 {
			return code
		}
		fmt.Fprintf(stderr, "scanner container exited with %d\n", code)
		return ExitScanError
	default:
		fmt.Fprintln(stderr, "docker:", err)
		return ExitScanError
	}
}

func dockerArgs(o ScanOptions, image string) []string {
	args := []string{
		"run", "--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "1024",
		"--memory", "6g",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=2g",
		"-v", o.Path + ":/work/src:ro",
		"-v", o.Out + ":/work/out",
		"--label", "scanx.scan=cli",
	}
	if runtime.GOOS == "linux" {
		// Write reports as the invoking user, not uid 65532.
		args = append(args, "--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()))
	}
	args = append(args, image, "scan", "--engine", "exec", "--path", "/work/src", "--out", "/work/out",
		"--format", strings.Join(o.Formats, ","), "--fail-on", o.FailOn, "--profile", o.Profile,
		"--history="+strconv.FormatBool(o.History), "--parallelism", strconv.Itoa(max(o.Parallelism, 1)))
	if o.SASTTimeout > 0 {
		args = append(args, "--sast-timeout", o.SASTTimeout.String())
	}
	if o.NoSnippets {
		args = append(args, "--no-snippets")
	}
	for _, ex := range o.Exclude {
		args = append(args, "--exclude", ex)
	}
	for flag, v := range map[string]string{
		"--branch": o.Branch, "--commit": o.Commit, "--repo": o.Repo,
		"--display-path": o.Path, "--display-out": o.Out,
	} {
		if v != "" {
			args = append(args, flag, v)
		}
	}
	return args
}

// scopeTree copies the listed files of src into a new directory under tmp so
// that every scanner sees only them, with unchanged relative paths. Paths
// escaping src, symlinks and non-regular files are ignored.
func scopeTree(src, listFile, tmp string) (string, int, error) {
	list, err := os.ReadFile(listFile) //nolint:gosec // path chosen by the worker
	if err != nil {
		return "", 0, err
	}
	dst := filepath.Join(tmp, "changed")
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return "", 0, err
	}
	n := 0
	for _, rel := range strings.Split(string(list), "\n") {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		from, err := finding.SafeJoin(src, rel)
		if err != nil {
			continue
		}
		st, err := os.Lstat(from) //nolint:gosec // from is confined to src by SafeJoin
		if err != nil || !st.Mode().IsRegular() || st.Size() > 20<<20 {
			continue
		}
		to := filepath.Join(dst, filepath.FromSlash(filepath.ToSlash(rel)))
		if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil { //nolint:gosec // rel already validated by SafeJoin
			return "", 0, err
		}
		if err := copyFile(from, to); err != nil {
			return "", 0, err
		}
		n++
	}
	return dst, n, nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from) //nolint:gosec // validated by SafeJoin
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640) //nolint:gosec // inside our temp dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
