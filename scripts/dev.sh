#!/usr/bin/env bash
# Run a Makefile target inside the scanX dev container (ADR-004).
#   scripts/dev.sh test
#   scripts/dev.sh lint
#   scripts/dev.sh test-integration   # starts a throwaway PostgreSQL
#   scripts/dev.sh shell              # interactive shell
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS path mangling.
if command -v cygpath >/dev/null 2>&1; then
  ROOT="$(cygpath -w "$ROOT")"
  export MSYS_NO_PATHCONV=1
fi

IMAGE=scanx-dev:local
docker build -q -t "$IMAGE" "$ROOT/build/dev" >/dev/null

RUN_ARGS=(--rm -v "$ROOT:/src" -w /src
  -v scanx-gomod-v3:/home/dev/go/pkg/mod -v scanx-gocache-v3:/home/dev/.cache/go-build)
if [ -t 0 ] && [ -t 1 ]; then RUN_ARGS+=(-it); fi

target="${1:-test}"
shift || true

if [ "$target" = "shell" ]; then
  exec docker run "${RUN_ARGS[@]}" "$IMAGE" bash
fi

if [ "$target" = "test-integration" ] && [ -z "${SCANX_TEST_DATABASE_URL:-}" ]; then
  NET=scanx-test-net
  PG=scanx-test-pg
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  docker rm -f "$PG" >/dev/null 2>&1 || true
  trap 'docker rm -f "$PG" >/dev/null 2>&1 || true' EXIT
  # FAKE credentials for a throwaway test database.
  docker run -d --name "$PG" --network "$NET" \
    -e POSTGRES_DB=scanx -e POSTGRES_USER=scanx -e POSTGRES_PASSWORD=FAKE-owner-pw \
    -e SCANX_APP_DB_PASSWORD=FAKE-app-pw \
    -v "$ROOT/deploy/postgres/init:/docker-entrypoint-initdb.d:ro" \
    postgres:16-alpine >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$PG" pg_isready -U scanx -d scanx >/dev/null 2>&1 \
      && docker exec "$PG" psql -U scanx -d scanx -tAc "select 1 from pg_roles where rolname='scanx_app'" 2>/dev/null | grep -q 1; then
      break
    fi
    sleep 1
  done
  RUN_ARGS+=(--network "$NET"
    -e "SCANX_TEST_DATABASE_ADMIN_URL=postgres://scanx:FAKE-owner-pw@$PG:5432/scanx?sslmode=disable"
    -e "SCANX_TEST_DATABASE_URL=postgres://scanx_app:FAKE-app-pw@$PG:5432/scanx?sslmode=disable")
fi

docker run "${RUN_ARGS[@]}" "$IMAGE" make "$target" "$@"
