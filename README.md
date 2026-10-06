<p align="center">
  <img src="internal/ui/static/img/scanx-mark.svg" alt="scanX" width="120">
</p>

<h1 align="center">scanX</h1>

<p align="center">
  <b>Self-hosted code security scanning.</b> Install on your own Linux server, connect your Git
  repositories, get one merged, de-duplicated security report from many open-source scanners.<br>
  <a href="docs/user/kurulum.md">🇹🇷 Türkçe kurulum kılavuzu</a> ·
  <a href="docs/user/install.md">🇬🇧 Installation guide</a>
</p>

---

> **Project status: Phase 0 of 8 — foundation.** The server, database, TLS proxy and installer
> skeleton run today; **scanning, the web UI and GitHub connection are not available yet**.
> Follow progress in [`TASKS.md`](TASKS.md) and the roadmap below. Do not use in production yet.

## What scanX does (target v1.0)

- 🔒 **Your code never leaves your server.** Each scan clones the repository into an isolated,
  network-less, throw-away container, scans it, then **deletes the code**. Only reports are kept.
- 🧰 **Many scanners, one report.** Opengrep/Semgrep, Gitleaks, Trivy, OSV-Scanner, Syft (SBOM),
  gosec, Bandit, Psalm, Checkov, Hadolint, ShellCheck and more — results are normalized,
  de-duplicated and prioritized.
- 🔗 **Connect GitHub / GitLab / Gitea / Bitbucket** with a read-only deploy key; scans run on push
  (only for the branches you choose), on a schedule, or from CI (GitHub Actions, GitLab CI).
- 🏢 **Multi-tenant:** organizations, roles, 2FA, audit log. One team never sees another's repos.
- 📊 New / fixed / existing findings between scans, quality gates that fail CI, SARIF, PDF, SBOM.

## Quick start (for DevOps — no programming needed)

You need a Linux server with **Docker** and **Docker Compose v2** (4 vCPU / 8 GB RAM / 50 GB disk
recommended) and `git`.

```bash
git clone https://github.com/ininia/scanx.git
cd scanx
./deploy/quickstart.sh --domain scan.yourcompany.com
```

The script builds scanX, generates all passwords and keys, creates a TLS certificate and starts
everything. When it finishes it prints the address and a one-time setup token.
**Back up `deploy/.env` immediately** — see the [installation guide](docs/user/install.md) for
firewall, real TLS certificates, updates, backups and troubleshooting.

## Roadmap

| Phase | Content | Status |
|---|---|---|
| 0 | Foundation: server, DB, TLS proxy, installer skeleton, CI | ✅ done |
| 1 | Scan engine + `scanx scan` CLI (Gitleaks, Opengrep, Trivy, OSV, Syft) | ⏳ next |
| 2 | Accounts, organizations, 2FA, web UI, setup wizard | |
| 3 | Isolated sandbox, Git + deploy keys, manual scans, report pages | |
| 4 | Webhooks (GitHub/GitLab/Gitea/Bitbucket), schedules, notifications | |
| 5 | GitHub Action, GitLab CI template, SARIF upload | |
| 6 | One-line `install.sh`, Let's Encrypt, backup/restore/update | |
| 7 | More scanners, PDF reports, trends, SonarQube, ZAP | |
| 8 | Hardening, docs, v1.0.0 | |

## License

scanX is **source-available** under the [Business Source License 1.1](LICENSE)
(Licensor: İninia Teknoloji Limited Şirketi).

- ✅ Free to use, including inside your company to scan your own code.
- ✅ Free to modify; contributions back to this repository are welcome.
- ❌ **Selling** scanX or a derivative, or offering it as a paid hosted/SaaS or paid scanning
  service, requires a commercial license from İninia Teknoloji Limited Şirketi.
- 🔓 Each version automatically becomes **AGPL-3.0-or-later** four years after release
  (current Change Date: 2030-10-06).

Third-party scanners keep their own licenses.

## Contributing & security

- Development needs only Docker: `scripts/dev.sh test | lint | test-integration`. See
  [CONTRIBUTING.md](CONTRIBUTING.md) (a CLA is required).
- Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).
- Architecture decisions: [`docs/adr/`](docs/adr) · Threat model:
  [`docs/security/threat-model.md`](docs/security/threat-model.md)
