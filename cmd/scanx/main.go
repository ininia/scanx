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
	"strings"
	"syscall"

	"github.com/ininia/scanx/internal/app"
	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/logging"
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
  server        Run the web/API server
  migrate       Apply DB migrations and exit
  healthcheck   Probe the local server (container HEALTHCHECK)
  gen-secrets   Print freshly generated secrets in .env format
  gen-cert      Generate a self-signed TLS certificate
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
