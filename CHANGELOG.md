# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: SemVer.

## [Unreleased]
### Added — Phase 1 (scan engine)
- `scanx scan`: local scanning with exec/docker engines, JSON / SARIF 2.1.0 / HTML reports, quality gate and exit codes.
- All-in-one scanner image with checksum/cosign-verified Opengrep, Gitleaks, Trivy, OSV-Scanner, Syft and offline vulnerability databases.
- 776 open-licensed SAST rules with a build-time license gate, plus scanX's own PHP taint rules.
- Normalized findings: severity mapping, line-independent fingerprints, cross-tool de-duplication, secret masking.
- `scripts/scan.sh` (Docker-only scanning), `scripts/e2e-scan.sh`, golden-file tests from real tool output.

### Added — Phase 0
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
- Snippets are masked for every finding category (a SAST match on a config line could expose a credential).
- Repository-supplied `.semgrepignore` / `.gitleaks.toml` / `.gitleaksignore` cannot hide findings.
- Scans run with no network, read-only root and source, all capabilities dropped, as a non-root user.
