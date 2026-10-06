#!/usr/bin/env bash
# End-to-end check of the scan engine (Faz 1 acceptance):
#   1. scan testdata/repos/php-vuln with the scanner image, sandboxed
#   2. verify the report against testdata/expected/php-vuln.json
# Requires only Docker. Usage: scripts/e2e-scan.sh [image]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-ghcr.io/ininia/scanx-scanner-all:dev}"
OUT="$ROOT/.e2e-out"
mkdir -p "$OUT"
chmod 0777 "$OUT" # the scanner runs as uid 65532

HOST_ROOT="$ROOT"
USER_ARGS=()
if command -v cygpath >/dev/null 2>&1; then
  HOST_ROOT="$(cygpath -w "$ROOT")"
  export MSYS_NO_PATHCONV=1
  USER_ARGS=(--user 0:0) # see scripts/dev.sh
fi
HOST_OUT="$HOST_ROOT/.e2e-out"

set +e
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=2g \
  -v "$HOST_ROOT/testdata/repos/php-vuln:/work/src:ro" -v "$HOST_OUT:/work/out" \
  "$IMAGE" scan --engine exec --path /work/src --out /work/out --fail-on high
code=$?
set -e
if [ "$code" -ne 1 ]; then
  echo "expected exit code 1 (quality gate failed on the vulnerable fixture), got $code" >&2
  exit 1
fi

docker build -q -t scanx-dev:local "$HOST_ROOT/build/dev" >/dev/null
docker run --rm "${USER_ARGS[@]}" -v "$HOST_ROOT:/src" -w /src -e SCANX_E2E_OUT=/src/.e2e-out \
  -v scanx-gomod-v3:/home/dev/go/pkg/mod -v scanx-gocache-v3:/home/dev/.cache/go-build \
  scanx-dev:local go test -tags e2e -count=1 -v ./test/e2e/
