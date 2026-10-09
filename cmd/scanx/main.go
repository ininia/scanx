// Command scanx is the single binary for the scanX platform:
// server, worker, CLI scanner and operational helpers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ininia/scanx/internal/app"
	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/gitfetch"
	"github.com/ininia/scanx/internal/logging"
	"github.com/ininia/scanx/internal/rules"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/version"
)

// Exit codes (spec §12.1).
const (
	exitOK        = 0
	exitGateFail  = 1
	exitScanError = 2
	exitConfig    = 3
)

const usage = `scanX — self-hosted code security scanning

Usage:
  scanx <command> [flags]

Commands:
  scan          Scan a source tree locally (code never leaves the machine)
  server        Run the web/API server
  worker        Run the scan worker (clones and scans repositories in sandboxes)
  git-fetch     Clone a repository for a scan (runs inside the scanner image)
  migrate       Apply DB migrations and exit
  healthcheck   Probe the local server (container HEALTHCHECK)
  gen-secrets   Print freshly generated secrets in .env format
  gen-cert      Generate a self-signed TLS certificate
  rules-bundle  Build the SAST rule bundle with the license gate (image build)
  version       Print version information
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "server":
		return withConfig(ctx, stderr, config.NeedDatabase|config.NeedKeys,
			func(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
				return app.RunServer(ctx, cfg, log)
			})
	case "worker":
		return withConfig(ctx, stderr, config.NeedDatabase|config.NeedKeys,
			func(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
				return app.RunWorker(ctx, cfg, log)
			})
	case "git-fetch":
		return gitfetch.Main(ctx, stdout, stderr)
	case "scan":
		return runScan(ctx, rest, stdout, stderr)
	case "migrate":
		return withConfig(ctx, stderr, config.NeedMigrations,
			func(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
				return store.Migrate(ctx, cfg.DatabaseAdminURL, log)
			})
	case "healthcheck":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.SetOutput(stderr)
		url := fs.String("url", "http://127.0.0.1:8080/health/live", "URL to probe")
		if err := fs.Parse(rest); err != nil {
			return exitConfig
		}
		if err := app.Healthcheck(ctx, *url); err != nil {
			fmt.Fprintln(stderr, err)
			return exitScanError
		}
		return exitOK
	case "gen-secrets":
		if err := app.GenerateSecrets(stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return exitScanError
		}
		return exitOK
	case "gen-cert":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.SetOutput(stderr)
		dir := fs.String("dir", ".", "output directory for cert.pem/key.pem")
		hosts := fs.String("hosts", "localhost,127.0.0.1", "comma-separated DNS names/IPs")
		ifMissing := fs.Bool("if-missing", false, "do nothing if a certificate already exists")
		if err := fs.Parse(rest); err != nil {
			return exitConfig
		}
		var hs []string
		for _, h := range strings.Split(*hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hs = append(hs, h)
			}
		}
		if err := app.GenerateSelfSignedCert(*dir, hs, *ifMissing); err != nil {
			fmt.Fprintln(stderr, err)
			return exitScanError
		}
		return exitOK
	case "rules-bundle":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.SetOutput(stderr)
		sourcesPath := fs.String("sources", "scanners/rules/sources.json", "rule sources manifest")
		out := fs.String("out", "rules-bundle", "output directory")
		if err := fs.Parse(rest); err != nil {
			return exitConfig
		}
		srcs, err := rules.LoadSources(*sourcesPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitConfig
		}
		m, err := rules.Bundle(filepath.Dir(*sourcesPath), *out, srcs)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitScanError
		}
		fmt.Fprintf(stdout, "bundled %d rule files (%d skipped: unknown license)\n", len(m.Rules), len(m.Skipped))
		return exitOK
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "scanx %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitConfig
	}
}

// withConfig loads + validates configuration, builds the logger and runs fn.
func withConfig(ctx context.Context, stderr io.Writer, req config.Requirement,
	fn func(context.Context, *config.Config, *slog.Logger) error,
) int {
	cfg, err := config.Load()
	if err == nil {
		err = cfg.Validate(req)
	}
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return exitConfig
	}
	log, err := logging.New(stderr, cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitConfig
	}
	slog.SetDefault(log)
	if err := fn(ctx, cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("fatal", "err", err)
		return exitScanError
	}
	return exitOK
}

// runScan parses `scanx scan` flags (spec §12.1).
func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := app.ScanOptions{}
	fs.StringVar(&o.Path, "path", ".", "source directory to scan")
	fs.StringVar(&o.Out, "out", "scanx-results", "output directory for reports")
	formats := fs.String("format", "json,sarif,html", "comma-separated report formats: json,sarif,html")
	fs.StringVar(&o.FailOn, "fail-on", "high", "fail (exit 1) on findings at or above: critical|high|medium|low|info|none")
	fs.StringVar(&o.Engine, "engine", "auto", "auto | exec (tools in this environment) | docker (scanner image)")
	fs.StringVar(&o.Image, "image", "", "scanner image for the docker engine (default "+app.DefaultScannerImage+")")
	fs.BoolVar(&o.History, "history", true, "scan git history for secrets")
	fs.StringVar(&o.Profile, "profile", "default", "fast | default | full")
	fs.BoolVar(&o.NoSnippets, "no-snippets", false, "do not store code snippets in reports")
	fs.IntVar(&o.Parallelism, "parallelism", 3, "scanners run in parallel")
	fs.DurationVar(&o.SASTTimeout, "sast-timeout", 20*time.Minute, "time limit for source-code analysis (opengrep)")
	fs.StringVar(&o.OnlyFiles, "only-files", "", "file listing repository-relative paths to scan (incremental scan)")
	fs.StringVar(&o.Branch, "branch", envFirst("SCANX_BRANCH", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME"), "branch name for the report")
	fs.StringVar(&o.Commit, "commit", envFirst("SCANX_COMMIT", "GITHUB_SHA", "CI_COMMIT_SHA"), "commit SHA for the report")
	fs.StringVar(&o.Repo, "repo", envFirst("SCANX_REPO", "GITHUB_REPOSITORY", "CI_PROJECT_PATH"), "repository name for the report")
	fs.StringVar(&o.DisplayPath, "display-path", "", "path shown in reports (set by the docker engine)")
	fs.StringVar(&o.DisplayOut, "display-out", "", "output path shown to the user (set by the docker engine)")
	fs.Func("exclude", "path or glob to exclude (repeatable)", func(v string) error {
		o.Exclude = append(o.Exclude, v)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	for _, f := range strings.Split(*formats, ",") {
		if f = strings.TrimSpace(f); f != "" {
			o.Formats = append(o.Formats, f)
		}
	}
	return app.RunScan(ctx, o, stdout, stderr)
}

func envFirst(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
