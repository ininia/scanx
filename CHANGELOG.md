# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: SemVer.

## [Unreleased]
### Added — scan quality and speed
- New analysers in the scanner image (checksum/hash pinned, offline): DevSkim, Bandit, Checkov, zizmor, Hadolint, ShellCheck, Lizard. Generic SARIF ingestion.
- Incremental scans on push: only the files changed by the push are scanned; issues are only marked fixed in touched files. Project setting for push scope; "Scan now" is a full scan.
- Live activity log on the scan page; per-project code-analysis time limit.
- Issue filters (severity, type, tool, status, new, search) and grouping (file + rule, rule, none).
- Category-based security score with grade A-F; code quality shown separately.

### Changed
- Opengrep loads only rules for languages present, limits effort per file, and skips vendored libraries, build output, generated code, assets and tool output (.sonarqube…).
- Gitleaks ignores EF Core generated files, vendored libraries and assets; secret findings show the masked source line.
- The worker finishes saving a completed scan when it is stopped.

### Added — Phases 3–4 (server-side scanning, webhooks, notifications)
- Per-project Ed25519 **deploy keys** (encrypted at rest, rotation) and pinned SSH host keys for GitHub, GitLab, Bitbucket and Codeberg (`SCANX_SSH_KNOWN_HOSTS` for others).
- `scanx worker`: Postgres job queue; each scan clones in a `git-fetch` container (egress-only network) and scans in a network-less, read-only, capability-free container; source code is deleted after every scan.
- Docker access only through a filtered docker-socket-proxy; leftover sandbox resources are reaped.
- "Scan now", connection test, live scan page, issue list with new/fixed tracking, issue triage (false positive / accepted risk / won't fix) with history, HTML/JSON/SARIF/SBOM report downloads.
- Push **webhooks** for GitHub, GitLab, Gitea/Forgejo, Bitbucket and a generic HMAC format, with branch filters (globs), delivery de-duplication and one active scan per commit.
- Notifications to Slack, Microsoft Teams, JSON webhooks and e-mail (SMTP) on completed scans, failed quality gates and failed scans.
- REST API: deploy key, scans, scan issues, reports, project issues, issue triage; OpenAPI updated.
- Quality gate and history scanning per project; dashboard shows open critical/high issues and recent scans.

### Security
- Outbound notification and Git connections refuse private/loopback/link-local addresses (SSRF), checked on the resolved IP.
- Webhook URLs/secrets and deploy keys are stored encrypted and never shown in error messages.

### Added — Phase 2 (server, accounts, multi-tenancy, web UI)
- First-run setup wizard (setup token → admin → mandatory 2FA → instance settings → first organization).
- Accounts with Argon2id passwords, TOTP 2FA, server-side sessions, account lockout and rate limiting.
- Organizations, roles (owner/admin/member/viewer), invitations without SMTP, personal API tokens, audit log.
- Projects (repository URL validation, branches) via web UI and REST API (`/api/v1`, OpenAPI 3.1 contract).
- Web interface in Turkish and English with the scanX brand design (dark theme, logo-derived colors).
- Row-level security on every tenant table; table-driven tenant isolation tests across all endpoints.

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
