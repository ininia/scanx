# syntax=docker/dockerfile:1.7
# scanX all-in-one scanner image (ADR-006).
# Every tool binary is verified against the official SHA256 checksum file of its
# release (opengrep: cosign signature verified, SHA256 pinned here). Bump a tool
# = change version + checksum + regenerate golden files.
# Build from the repository root:
#   docker build -f scanners/all-in-one/Dockerfile -t ghcr.io/ininia/scanx-scanner-all:dev .

# ---------- scanx binary ----------
FROM golang:1.27-alpine AS scanx
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-buildvcs=false
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -X github.com/ininia/scanx/internal/version.Version=${VERSION}" \
      -o /out/scanx ./cmd/scanx

# ---------- verified tool downloads ----------
FROM debian:bookworm-slim AS fetch
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*
ARG OPENGREP_VERSION=1.30.0
ARG OPENGREP_SHA256=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG OSV_VERSION=2.6.0
ARG OSV_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
ARG SYFT_VERSION=1.54.0
ARG SYFT_SHA256=54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860
WORKDIR /dl
RUN set -eu; \
    dl() { curl -fsSL --retry 3 -o "$2" "$1"; echo "$3  $2" | sha256sum -c -; }; \
    GH=https://github.com; mkdir -p /out/bin; \
    dl "$GH/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" opengrep "$OPENGREP_SHA256"; \
    install -m 0755 opengrep /out/bin/opengrep; \
    dl "$GH/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks.tgz "$GITLEAKS_SHA256"; \
    tar -xzf gitleaks.tgz -C /out/bin gitleaks; \
    dl "$GH/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy.tgz "$TRIVY_SHA256"; \
    tar -xzf trivy.tgz -C /out/bin trivy; \
    dl "$GH/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" osv-scanner "$OSV_SHA256"; \
    install -m 0755 osv-scanner /out/bin/osv-scanner; \
    dl "$GH/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" syft.tgz "$SYFT_SHA256"; \
    tar -xzf syft.tgz -C /out/bin syft; \
    chmod 0755 /out/bin/*

# ---------- rule repositories at pinned commits + license gate ----------
FROM fetch AS rules
COPY scanners/rules /build/rules
RUN set -eu; cd /build/rules; \
    fetch() { mkdir -p "src/$1"; git -C "src/$1" init -q; git -C "src/$1" remote add origin "$2"; \
              git -C "src/$1" fetch -q --depth 1 origin "$3"; git -C "src/$1" checkout -q FETCH_HEAD; }; \
    fetch gitlab      https://gitlab.com/gitlab-org/security-products/sast-rules.git 53bf5cf6df3c51b6c02110f5a638b5e6213666cd; \
    fetch trailofbits https://github.com/trailofbits/semgrep-rules.git               31390b3a99c04c81522d1b37c8d1900aa2dd4094; \
    fetch dgryski     https://github.com/dgryski/semgrep-go.git                      db0227c03f4b3c4e71d900188d51db4c81d66932; \
    fetch 0xdea       https://github.com/0xdea/semgrep-rules.git                     dae50da6e6e629750f1daec73a01ef9206a372ab; \
    fetch elttam      https://github.com/elttam/semgrep-rules.git                    244268562cc92d33f54b8a60a187df5520f91b26
COPY --from=scanx /out/scanx /usr/local/bin/scanx
RUN scanx rules-bundle --sources /build/rules/sources.json --out /out/rules

# ---------- offline vulnerability databases ----------
FROM fetch AS db
COPY --from=fetch /out/bin/trivy /usr/local/bin/trivy
# Change DB_DATE to force a refresh of the baked databases.
ARG DB_DATE=2026-10-06
RUN set -eu; echo "db snapshot ${DB_DATE}"; \
    trivy image --download-db-only --cache-dir /out/trivy --no-progress; \
    for e in Packagist npm PyPI Go Maven crates.io RubyGems NuGet; do \
      mkdir -p "/out/osv/osv-scalibr/$e"; \
      curl -fsSL --retry 3 -o "/out/osv/osv-scalibr/$e/all.zip" "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"; \
    done; \
    date -u +%Y-%m-%dT%H:%M:%SZ > /out/DB_BUILT_AT

# ---------- final image ----------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 65532 scanx && useradd -u 65532 -g 65532 -M -d /nonexistent -s /usr/sbin/nologin scanx
COPY --from=fetch /out/bin/ /usr/local/bin/
COPY --from=scanx /out/scanx /usr/local/bin/scanx
COPY --from=rules /out/rules /opt/scanx/rules
COPY --from=db /out/trivy /opt/scanx/db/trivy
COPY --from=db /out/osv /opt/scanx/db/osv
COPY --from=db /out/DB_BUILT_AT /opt/scanx/db/DB_BUILT_AT
COPY scanners/all-in-one/config /opt/scanx/config
# Opengrep unpacks itself into $HOME/.cache on first run; do it at build time so
# the runtime filesystem can stay read-only.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    SCANX_TOOL_HOME=/opt/scanx/home \
    SCANX_RULES_DIR=/opt/scanx/rules \
    SCANX_DB_DIR=/opt/scanx/db \
    SCANX_CONFIG_DIR=/opt/scanx/config
RUN mkdir -p /opt/scanx/home && HOME=/opt/scanx/home opengrep --version \
 && chmod -R a+rX /opt/scanx && chmod -R a-w /opt/scanx
LABEL org.opencontainers.image.title="scanX scanner (all-in-one)" \
      org.opencontainers.image.source="https://github.com/ininia/scanx" \
      org.opencontainers.image.licenses="BUSL-1.1"
USER 65532:65532
# Batch job: no long-running process to probe.
HEALTHCHECK NONE
WORKDIR /tmp
ENTRYPOINT ["scanx"]
CMD ["scan", "--engine", "exec", "--path", "/work/src", "--out", "/work/out"]
