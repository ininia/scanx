package app

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/sandbox"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/worker"
)

// RunWorker runs the scan worker until ctx is cancelled.
func RunWorker(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.MigrationsCurrent(ctx, pool); err != nil {
		return fmt.Errorf("%w (run `scanx migrate` first)", err)
	}
	key, err := cfg.MasterKeyBytes()
	if err != nil {
		return err
	}
	box, err := crypto.New(key)
	if err != nil {
		return err
	}
	docker, err := sandbox.NewClient(cfg.DockerHost)
	if err != nil {
		return err
	}
	mem, err := ParseBytes(cfg.ScannerMemory)
	if err != nil {
		return fmt.Errorf("SCANX_SCANNER_MEMORY: %w", err)
	}
	w := worker.New(&store.DB{Pool: pool}, box, docker, NewNotifier(cfg), worker.Config{
		Image: cfg.ScannerImage, EgressNetwork: cfg.EgressNetwork, KnownHostsExtra: cfg.SSHKnownHosts,
		Concurrency: cfg.WorkerConcurrency, ScanTimeout: cfg.ScanTimeout, MemoryBytes: mem,
		NanoCPUs: int64(cfg.ScannerCPUs * 1e9), MaxRepoMB: cfg.MaxRepoMB, CloneDepth: cfg.CloneDepth,
		Runtime: cfg.SandboxRuntime, Profile: cfg.ScannerProfile, Parallelism: cfg.ScannerParallelism,
		AllowPrivateGitHosts: cfg.AllowPrivateGitHosts, BaseURL: cfg.BaseURL,
	}, log)
	return w.Run(ctx)
}

// NewNotifier builds the notification sender from SCANX_SMTP_* settings.
func NewNotifier(cfg *config.Config) *notify.Sender {
	return notify.NewSender(notify.SMTP{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword.Reveal(),
		From: cfg.SMTPFrom, TLS: cfg.SMTPTLS,
	}, false)
}

// ParseBytes parses Docker-style sizes: "512m", "2g", "1073741824".
func ParseBytes(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		mult, s = 1<<30, strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		mult, s = 1<<20, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		mult, s = 1<<10, strings.TrimSuffix(s, "k")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	b := int64(n * float64(mult))
	if b < 256<<20 {
		return 0, fmt.Errorf("at least 256m is required")
	}
	return b, nil
}
