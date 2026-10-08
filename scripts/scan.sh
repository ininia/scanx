#!/usr/bin/env bash
# Scan a local folder with scanX using only Docker (no Go, no installs).
# The code is mounted read-only into a network-less, throw-away container.
#
#   ./scripts/scan.sh /path/to/your/repo            # reports in ./scanx-results
#   ./scripts/scan.sh /path/to/repo --fail-on critical --profile full
#
# Any extra flags are passed to `scanx scan` (see `scanx scan -h`).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
shift || true
IMAGE="${SCANX_SCANNER_IMAGE:-ghcr.io/ininia/scanx-scanner-all:dev}"
OUT="${SCANX_OUT:-$PWD/scanx-results}"

[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 3; }
TARGET="$(cd "$TARGET" && pwd)"
mkdir -p "$OUT"
chmod 0777 "$OUT" # the scanner runs as an unprivileged user

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "==> Building the scanner image (first run downloads tools and vulnerability databases, ~5-10 min)…"
  docker build -f "$ROOT/scanners/all-in-one/Dockerfile" -t "$IMAGE" "$ROOT"
fi

HT="$TARGET" HO="$OUT"
if command -v cygpath >/dev/null 2>&1; then
  HT="$(cygpath -w "$TARGET")"
  HO="$(cygpath -w "$OUT")"
  export MSYS_NO_PATHCONV=1
fi

exec docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 1024 --tmpfs /tmp:rw,noexec,nosuid,size=2g \
  -v "$HT:/work/src:ro" -v "$HO:/work/out" \
  "$IMAGE" scan --engine exec --path /work/src --out /work/out \
  --display-path "$TARGET" --display-out "$OUT" "$@"
