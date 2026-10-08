# scanX Installation Guide (for DevOps)

No programming knowledge needed — just a Linux server and Docker. The Turkish version is
[kurulum.md](kurulum.md).

> **Status (Phase 4):** the server clones repositories with a read-only deploy key and scans them in
> isolated containers — "Scan now", scan-on-push webhooks, result pages, HTML/JSON/SARIF/SBOM reports
> and Slack/Teams/e-mail notifications work. See section 6 to connect GitHub.

## 1. Requirements
- Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/Alma 9 or Amazon Linux 2023
- 2 vCPU / **4 GB RAM** / 40 GB disk minimum (4 / 8 / 100 recommended). With 1 GB RAM the UI
  works but scans cannot run (the scanners need ~3 GB, `SCANX_SCANNER_MEMORY`).
- Docker Engine 24+, Docker Compose v2, git, curl; ports 80 and 443 reachable

No Docker yet? `curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker $USER`, then log out and in.

## 2. Install
```bash
git clone https://github.com/ininia/scanx.git
cd scanx
./deploy/quickstart.sh --domain scan.yourcompany.com
```
Use the server IP if you have no domain. If 80/443 are taken: `--http-port 8080 --https-port 8443`.

**Back up `deploy/.env` right away** (password manager / vault). It holds all passwords and
`SCANX_MASTER_KEY`; if lost, stored repository keys cannot be decrypted. Never commit or share it.

## 3. Verify
```bash
curl -k https://localhost/health/ready
# {"status":"ok",...,"checks":{"database":"ok","migrations":"ok"}}
```

## 4. Operations
All commands from the repository folder; `C="docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env"`.

| Task | Command |
|---|---|
| Status / logs | `$C ps` · `$C logs -f --tail 100` |
| Stop / start | `$C down` · `./deploy/quickstart.sh` |
| Update | `git pull && ./deploy/quickstart.sh` |
| DB backup | `$C exec -T postgres pg_dump -U scanx -Fc scanx > scanx-$(date +%F).dump` |

Services restart automatically after a reboot (`sudo systemctl enable docker`). `down -v` deletes all data.

## 5. TLS
A self-signed certificate is created automatically. To use your own, copy `cert.pem`/`key.pem` into
the `scanx_certs` volume and restart nginx (see the Turkish guide §5 for the exact command).
Let's Encrypt automation comes in Phase 6.

## 6. Connect GitHub and scan automatically
1. **Projects → Add project**, paste the repository URL. Private repos: SSH URL
   (`git@github.com:company/app.git`); public repos may use the https URL (no key needed).
2. SSH only: copy the `ssh-ed25519 …` line from the **Deploy key** card. GitHub → repo
   **Settings → Deploy keys → Add deploy key**, title `scanX`, **do not** allow write access.
   Back in scanX press **Test connection** → "Connection works ✓".
3. Pick a branch and press **Scan now**. The scan page updates itself (queued → cloning → scanning
   → reporting → completed). The source code is deleted from the server after each scan.
4. Webhook: copy the URL and the secret from the **Webhook** card. GitHub → **Settings → Webhooks →
   Add webhook**: Payload URL, Content type `application/json`, Secret, "Just the push event"
   (disable SSL verification only while you use the self-signed certificate). Every push to the
   selected branches now starts a scan.
5. **Notifications → Add channel**: Slack/Teams incoming-webhook URL, JSON webhook or e-mail
   (`SCANX_SMTP_*` in `deploy/.env`).

Self-hosted GitLab/Gitea on an internal network: set `SCANX_ALLOW_PRIVATE_GIT_HOSTS=true` and put
the output of `ssh-keyscan git.example.local` into `SCANX_SSH_KNOWN_HOSTS` (lines joined with `\n`).
