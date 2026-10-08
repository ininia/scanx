#!/bin/sh
# Regenerates scanner golden files from REAL tool runs (spec rule: never invent
# tool output formats). Runs inside the scanner image:
#
#   docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=1g \
#     -v "$PWD/testdata/repos/php-vuln:/work/src:ro" -v "$PWD/testdata/scanner-outputs:/work/out" \
#     -e HOME=/tmp -v "$PWD/scripts:/scripts:ro" --entrypoint sh \
#     ghcr.io/ininia/scanx-scanner-all:dev /scripts/capture-golden.sh
#
# Commands mirror the adapters in internal/scanner/*.
set -u
OUT=/work/out
SRC=/work/src
CFG=/opt/scanx/config
mkdir -p "$OUT/gitleaks" "$OUT/opengrep" "$OUT/trivy" "$OUT/osv" "$OUT/syft"

gitleaks dir "$SRC" -c "$CFG/gitleaks.toml" -i "$CFG/gitleaksignore" -f json \
  -r "$OUT/gitleaks/dir.json" --redact --no-banner --exit-code 0 --max-target-megabytes 10 2>/dev/null
echo "gitleaks dir: $?"

# Git history fixture: a secret committed, then replaced by an env lookup.
H=/tmp/history-repo
mkdir -p "$H"
git -C "$H" init -q
git -C "$H" config user.email fixture@example.test
git -C "$H" config user.name fixture
# FAKE value, assembled at runtime so this script itself is not flagged.
FIXTURE_VALUE="Qm7Xv2Lp9Tz4""Rk8Wn1Bs6Jd3Hf5Yc0Ge"
printf '<?php\n$deploy_token = "%s"; // FAKE\n' "$FIXTURE_VALUE" > "$H/deploy.php"
git -C "$H" add deploy.php
git -C "$H" commit -qm "add deploy token"
printf '%s\n' '<?php' '$deploy_token = getenv("DEPLOY_TOKEN");' > "$H/deploy.php"
git -C "$H" commit -qam "read token from env"
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
  gitleaks git "$H" -c "$CFG/gitleaks.toml" -i "$CFG/gitleaksignore" -f json \
  -r "$OUT/gitleaks/git.json" --redact --no-banner --exit-code 0 --log-opts=--all 2>/dev/null
echo "gitleaks git: $?"

XDG_CACHE_HOME=/opt/scanx/home/.cache opengrep scan --config /opt/scanx/rules \
  --json-output="$OUT/opengrep/php-vuln.json" --quiet --taint-intrafile --x-ignore-semgrepignore-files \
  --timeout 30 --max-target-bytes 5000000 --exclude node_modules --exclude vendor "$SRC" >/dev/null 2>/tmp/opengrep.err
echo "opengrep: $?"
tail -n 3 /tmp/opengrep.err

trivy fs "$SRC" --scanners vuln,misconfig,secret,license --cache-dir /opt/scanx/db/trivy \
  --cache-backend memory --skip-db-update --skip-java-db-update --skip-check-update --offline-scan \
  --skip-version-check --disable-telemetry --format json --output "$OUT/trivy/php-vuln.json" --exit-code 0 --quiet
echo "trivy: $?"

OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/scanx/db/osv osv-scanner scan source -r --offline \
  --format json --output-file "$OUT/osv/php-vuln.json" "$SRC" >/dev/null 2>&1
echo "osv-scanner: $? (1 = vulnerabilities found)"

SYFT_CHECK_FOR_APP_UPDATE=false XDG_CACHE_HOME=/tmp/syft-cache syft "dir:$SRC" \
  -o "cyclonedx-json=$OUT/syft/php-vuln.cdx.json" -q
echo "syft: $?"

# Empty-input variants (every adapter needs a "no findings" golden file).
E=/tmp/empty-repo
mkdir -p "$E"
printf '%s\n' '# nothing to see here' > "$E/README.md"
gitleaks dir "$E" -c "$CFG/gitleaks.toml" -i "$CFG/gitleaksignore" -f json \
  -r "$OUT/gitleaks/empty.json" --redact --no-banner --exit-code 0 2>/dev/null
XDG_CACHE_HOME=/opt/scanx/home/.cache opengrep scan --config /opt/scanx/rules/scanx \
  --json-output="$OUT/opengrep/empty.json" --quiet "$E" >/dev/null 2>&1
trivy fs "$E" --scanners vuln,misconfig,secret,license --cache-dir /opt/scanx/db/trivy \
  --cache-backend memory --skip-db-update --skip-java-db-update --skip-check-update --offline-scan \
  --skip-version-check --disable-telemetry --format json --output "$OUT/trivy/empty.json" --exit-code 0 --quiet
printf '%s\n' '{"name":"empty","require":{}}' > "$E/composer.json"
printf '%s\n' '{"packages":[],"packages-dev":[]}' > "$E/composer.lock"
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/scanx/db/osv osv-scanner scan source -r --offline \
  --format json --output-file "$OUT/osv/empty.json" "$E" >/dev/null 2>&1
echo "osv-scanner empty: $? (128 = no packages)"
echo "empty variants done"
