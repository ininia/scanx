package app

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ininia/scanx/internal/api"
	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/web"
)

// BuildHandler assembles the full HTTP handler (API + UI + middleware).
func BuildHandler(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) (http.Handler, error) {
	key, err := cfg.MasterKeyBytes()
	if err != nil {
		return nil, err
	}
	box, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	scfg := service.DefaultConfig()
	scfg.SetupToken = cfg.SetupToken.Reveal()
	scfg.AllowOrgCreation = cfg.AllowSignup
	svc := service.New(&store.DB{Pool: pool}, box, scfg, log)
	svc.SetNotifier(NewNotifier(cfg))
	if n, err := svc.EnsureProjectCredentials(context.Background()); err != nil {
		log.Error("backfill project credentials", "err", err)
	} else if n > 0 {
		log.Info("created missing deploy keys / webhook secrets", "projects", n)
	}

	secure := strings.HasPrefix(cfg.BaseURL, "https://")
	cookies := server.NewCookies(secure)
	sessionKey := []byte(cfg.SessionKey.Reveal())
	apiH := &api.Handler{Svc: svc, Cookies: cookies}
	webH := &web.Handler{
		Svc: svc, Cookies: cookies, SessionKey: sessionKey, Require2FA: scfg.RequireAdmin2FA,
		KnownHostsExtra: cfg.SSHKnownHosts, SMTPConfigured: cfg.SMTPHost != "" && cfg.SMTPFrom != "",
	}
	return server.New(server.Options{
		HSTS: secure,
		ReadyChecks: []server.Check{
			{Name: "database", Fn: pool.Ping},
			{Name: "migrations", Fn: func(ctx context.Context) error { return store.MigrationsCurrent(ctx, pool) }},
		},
		API:        apiH.Mount,
		Web:        webH.Mount,
		Middleware: []func(http.Handler) http.Handler{server.Authenticate(svc, cookies), server.CSRF(sessionKey, cookies)},
	}), nil
}

// cleanupSessions deletes expired sessions hourly.
func cleanupSessions(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	d := &store.DB{Pool: pool}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		_ = d.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
			n, err := q.DeleteExpiredSessions(ctx)
			if err == nil && n > 0 {
				log.InfoContext(ctx, "expired sessions removed", "count", n)
			}
			return err
		})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
