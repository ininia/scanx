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

> **Project status: Phase 4 of 8.** Working today: connect a GitHub/GitLab/Gitea/Bitbucket repository
> with a read-only **deploy key**, press **Scan now** or let **push webhooks** start scans; the server
> clones and scans in throw-away sandboxed containers and shows results, new/fixed issues, triage and
> HTML/JSON/SARIF/SBOM reports, with Slack/Teams/e-mail notifications. Plus setup wizard, accounts +
> 2FA, organizations, roles, API tokens and audit log (Turkish / English UI).
> Follow progress in [`TASKS.md`](TASKS.md) and the roadmap below.

## Scan a repository now (only Docker needed)

```bash
git clone https://github.com/ininia/scanx.git
./scanx/scripts/scan.sh /path/to/your/repo
```

Your code is mounted **read-only** into a throw-away container with **no network**; nothing
leaves your machine. Reports land in `./scanx-results/` (`scanx.html`, `scanx.json`,
`scanx.sarif`, `sbom.cdx.json`). Exit code: `0` passed, `1` quality gate failed (default: any
high or critical finding), `2` scan error, `3` bad options. See an
[example report](docs/examples/php-vuln-report.html) of the bundled vulnerable fixture.

Scanners in this release: **Opengrep** (multi-language SAST with 776 open-licensed rules, incl.
scanX's own PHP taint rules), **Gitleaks** (working tree + git history), **Trivy** (dependencies,
IaC, secrets, licenses), **OSV-Scanner** (dependencies, second opinion) and **Syft** (SBOM).
Findings from different tools are merged into one issue.

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

## Install the server (for DevOps — no programming needed)

You need a Linux server with **Docker** and **Docker Compose v2** (at least 4 GB RAM for scanning;
4 vCPU / 8 GB RAM / 100 GB disk recommended) and `git`.

```bash
git clone https://github.com/ininia/scanx.git
cd scanx
./deploy/quickstart.sh --domain scan.yourcompany.com
```

The script builds scanX, generates all passwords and keys, creates a TLS certificate and starts
everything. When it finishes it prints the address and a one-time setup token: open the address,
enter the token and the **setup wizard** walks you through the administrator account (with
mandatory 2FA), instance settings and your first organization.
Then add a project, add the shown deploy key and webhook in GitHub — the guide walks through it.
**Back up `deploy/.env` immediately** — see the [installation guide](docs/user/install.md) for
firewall, real TLS certificates, updates, backups and troubleshooting.

## Roadmap

| Phase | Content | Status |
|---|---|---|
| 0 | Foundation: server, DB, TLS proxy, installer skeleton, CI | ✅ done |
| 1 | Scan engine + `scanx scan` CLI (Gitleaks, Opengrep, Trivy, OSV, Syft) | ✅ done |
| 2 | Accounts, organizations, 2FA, web UI, setup wizard | ✅ done |
| 3 | Isolated sandbox, Git + deploy keys, manual scans, report pages | ✅ done |
| 4 | Webhooks (GitHub/GitLab/Gitea/Bitbucket), notifications (schedules: next) | ✅ done |
| 5 | GitHub Action, GitLab CI template, SARIF upload, scheduled scans | ⏳ next |
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
