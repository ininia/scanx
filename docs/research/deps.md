# Go dependencies

Checked 2026-10-06 (versions resolved by `go get @latest` in golang:1.27.1).

| Module | Version | License | Purpose | Notes |
|---|---|---|---|---|
| github.com/go-chi/chi/v5 | v5.3.2 | MIT | HTTP router | stdlib-compatible, widely used |
| github.com/jackc/pgx/v5 | v5.11.0 | MIT | PostgreSQL driver/pool | `stdlib.OpenDBFromPool`: closing the `*sql.DB` does **not** close the pool (verified in source) |
| github.com/pressly/goose/v3 | v3.28.0 | MIT | Migrations | Provider API verified in source: `NewProvider`, `Up`, `GetVersions` (no lock), `WithSessionLocker(lock.NewPostgresSessionLocker())`; `Provider.Close` closes the given `*sql.DB` |
| github.com/caarlos0/env/v11 | v11.4.1 | MIT | Env config | `Options.Prefix`, `Options.Environment` for tests |
| github.com/google/uuid | v1.6.0 | BSD-3 | UUID (v7) | used from Faz 2 |

Transitive deps pulled by goose include `modernc.org/sqlite` (BSD-3) for its other dialects;
acceptable, revisit binary size later.

Tooling (dev image only, not shipped): golangci-lint v2.14.0 (GPL-3.0, build tool), gofumpt (BSD-3).
