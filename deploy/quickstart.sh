#!/usr/bin/env bash
# scanX quick start: builds the image, generates secrets once, starts the stack.
# Safe to re-run: existing deploy/.env and data are kept.
#
#   ./deploy/quickstart.sh                                  # https://localhost
#   ./deploy/quickstart.sh --domain scan.example.com        # your server name
#   ./deploy/quickstart.sh --http-port 8080 --https-port 8443
#   ./deploy/quickstart.sh --skip-scanner                   # do not (re)build the scanner image
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
PROJECT="${SCANX_PROJECT:-scanx}"
DOMAIN="" HTTP_PORT="" HTTPS_PORT="" SKIP_SCANNER=0

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain)     DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
    --http-port)  HTTP_PORT="${2:?--http-port needs a value}"; shift 2 ;;
    --https-port) HTTPS_PORT="${2:?--https-port needs a value}"; shift 2 ;;
    --skip-scanner) SKIP_SCANNER=1; shift ;;
    -h|--help)    sed -n '2,9p' "$0"; exit 0 ;;
    *)            die "unknown option: $1 (see --help)" ;;
  esac
done

if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9.-]{1,253}$'; then
  die "invalid --domain '$DOMAIN'"
fi
for p in "$HTTP_PORT" "$HTTPS_PORT"; do
  if [ -n "$p" ] && ! printf '%s' "$p" | grep -Eq '^[0-9]{1,5}$'; then die "invalid port '$p'"; fi
done

command -v docker >/dev/null 2>&1 || die "Docker is not installed. See https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker is installed but not running, or this user cannot access it (try sudo)."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing (the 'docker compose' plugin)."

# Scans need memory: ~1.5 GB for scanX itself plus SCANX_SCANNER_MEMORY (3 GB).
MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
if [ "${MEM_KB:-0}" -gt 0 ] && [ "$MEM_KB" -lt 3500000 ]; then
  warn "This server has $((MEM_KB / 1024)) MB RAM. The web interface works, but scans need at least 4 GB"
  warn "(recommended 8 GB). Resize the server, or set SCANX_SCANNER_MEMORY lower in deploy/.env."
fi

IMAGE="ghcr.io/ininia/scanx:${SCANX_VERSION:-dev}"
SCANNER_IMAGE="ghcr.io/ininia/scanx-scanner-all:${SCANX_VERSION:-dev}"
say "Building scanX image ($IMAGE) — first run takes a few minutes"
docker build -q -t "$IMAGE" "$ROOT_DIR" >/dev/null

if [ "$SKIP_SCANNER" = 0 ]; then
  say "Building the scanner image ($SCANNER_IMAGE): security tools + vulnerability databases."
  say "First run downloads ~1.5 GB and takes 10–20 minutes; later runs are fast (cached)."
  docker build -q -f "$ROOT_DIR/scanners/all-in-one/Dockerfile" -t "$SCANNER_IMAGE" "$ROOT_DIR" >/dev/null     || die "scanner image build failed (re-run to retry; check disk space with: df -h)"
fi

set_var() { # set_var KEY VALUE  (replace or append in .env)
  if grep -q "^$1=" "$ENV_FILE"; then
    sed -i.bak "s|^$1=.*|$1=$2|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
}

if [ ! -f "$ENV_FILE" ]; then
  say "Creating deploy/.env with freshly generated secrets"
  umask 077
  cp "$DEPLOY_DIR/.env.example" "$ENV_FILE"
  docker run --rm "$IMAGE" gen-secrets >> "$ENV_FILE"
  NEW_INSTALL=1
else
  say "Keeping existing deploy/.env"
  NEW_INSTALL=0
fi

if [ -n "$DOMAIN" ]; then set_var SCANX_DOMAIN "$DOMAIN"; fi
if [ -n "$HTTP_PORT" ]; then set_var SCANX_HTTP_PORT "$HTTP_PORT"; fi
if [ -n "$HTTPS_PORT" ]; then set_var SCANX_HTTPS_PORT "$HTTPS_PORT"; fi
# Keep BASE_URL consistent with domain/port.
get_var() { grep "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }
D="$(get_var SCANX_DOMAIN)"; D="${D:-localhost}"
P="$(get_var SCANX_HTTPS_PORT)"; P="${P:-443}"
if [ "$P" = "443" ]; then set_var SCANX_BASE_URL "https://$D"; else set_var SCANX_BASE_URL "https://$D:$P"; fi
if ! grep -q "^SCANX_SCANNER_IMAGE=" "$ENV_FILE"; then set_var SCANX_SCANNER_IMAGE "$SCANNER_IMAGE"; fi

say "Starting scanX"
docker compose -p "$PROJECT" -f "$DEPLOY_DIR/docker-compose.yml" --env-file "$ENV_FILE" up -d

BASE="$(get_var SCANX_BASE_URL)"
say "Waiting for scanX to become ready"
for _ in $(seq 1 60); do
  if curl -fsk "https://127.0.0.1:$P/health/ready" >/dev/null 2>&1; then
    printf '\n\033[1;32m✔ scanX is running:\033[0m %s\n' "$BASE"
    if [ "$NEW_INSTALL" = 1 ]; then
      printf '\n\033[1;33m⚠  IMPORTANT:\033[0m back up %s now (especially SCANX_MASTER_KEY).\n' "$ENV_FILE"
      printf '   If it is lost, stored repository keys can never be decrypted.\n'
      printf '   One-time setup token: %s\n' "$(get_var SCANX_SETUP_TOKEN)"
    fi
    printf '   The certificate is self-signed: your browser will warn once.\n\n'
    exit 0
  fi
  sleep 2
done
warn "scanX did not become ready in time. Recent logs:"
docker compose -p "$PROJECT" -f "$DEPLOY_DIR/docker-compose.yml" --env-file "$ENV_FILE" logs --tail 50
exit 1
