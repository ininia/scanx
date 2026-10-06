# scanX Installation Guide (for DevOps)

No programming knowledge needed — just a Linux server and Docker. The Turkish version is
[kurulum.md](kurulum.md).

> **Status (Phase 0):** this release installs and runs the server, database and HTTPS layer.
> Scanning, the web UI and GitHub connection arrive in later phases; this guide is updated each phase.

## 1. Requirements
- Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/Alma 9 or Amazon Linux 2023
- 4 vCPU / 8 GB RAM / 50 GB disk minimum (8 / 16 / 200 recommended)
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

## Coming soon: connecting GitHub (Phases 3–4)
Add project → paste repo URL → add the shown **read-only deploy key** in GitHub
(Settings → Deploy keys) → test connection → pick branches → add the shown **webhook** in GitHub
(Settings → Webhooks, push events). Every push to the selected branches then triggers a scan.
