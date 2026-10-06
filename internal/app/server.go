// Package app wires configuration, storage and HTTP together for each
// command of the scanx binary.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/store"
)

// RunServer serves HTTP until ctx is cancelled, shutting down gracefully.
// Migrations normally run in the separate `migrate` container (ADR-005); they
// are applied here only if an admin URL is explicitly configured (dev use).
func RunServer(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if !cfg.DatabaseAdminURL.IsZero() {
		if err := store.Migrate(ctx, cfg.DatabaseAdminURL, log); err != nil {
			return err
		}
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.MigrationsCurrent(ctx, pool); err != nil {
		return fmt.Errorf("%w (run `scanx migrate` first)", err)
	}

	handler := server.New(server.Options{
		HSTS: strings.HasPrefix(cfg.BaseURL, "https://"),
		ReadyChecks: []server.Check{
			{Name: "database", Fn: pool.Ping},
			{Name: "migrations", Fn: func(ctx context.Context) error { return store.MigrationsCurrent(ctx, pool) }},
		},
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.InfoContext(ctx, "http server listening", "addr", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	return nil
}
