# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: SemVer.

## [Unreleased]
### Added
- Phase 0 skeleton: single `scanx` binary (`server`, `migrate`, `healthcheck`, `gen-secrets`, `gen-cert`, `version`).
- Config loading/validation for all `SCANX_*` variables; `Secret` type and log redaction.
- HTTP server with `/health/live`, `/health/ready`, JSON error envelope, request IDs, security headers.
- PostgreSQL migrations (goose, embedded) with row-level security on tenant tables and a non-privileged runtime role.
- Distroless non-root image; docker compose stack (nginx TLS, one-shot migrate, server, postgres).
- Docker-only dev workflow (`scripts/dev.sh`), golangci-lint config, GitHub Actions CI.
- Brand design tokens derived from the scanX logo.
- Licensed under Business Source License 1.1 (Change License: AGPL-3.0-or-later on 2030-10-06).

### Security
- Internet-facing server holds no schema-owner/superuser DB credentials (ADR-005).
