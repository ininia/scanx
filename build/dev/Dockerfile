# scanX development image: Go toolchain + make + linters.
# Used by scripts/dev.sh so contributors only need Docker (ADR-004).
FROM golang:1.27-alpine

RUN apk add --no-cache make git bash ca-certificates build-base

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false \
    GOCACHE=/home/dev/.cache/go-build \
    GOMODCACHE=/home/dev/go/pkg/mod \
    GOPATH=/home/dev/go \
    PATH=/home/dev/go/bin:/usr/local/go/bin:$PATH

# Run as an unprivileged user; cache directories are pre-created so named
# volumes mounted there inherit the user's ownership.
RUN adduser -D -u 1000 dev \
 && mkdir -p /home/dev/.cache/go-build /home/dev/go/pkg/mod /src \
 && chown -R dev:dev /home/dev /src
USER dev

# Linters are built with the same Go version so they understand go1.27 code.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest \
 && go install mvdan.cc/gofumpt@latest \
 && go install github.com/a-h/templ/cmd/templ@v0.3.1070 \
 && CGO_ENABLED=1 go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 \
 && go clean -cache -modcache \
 && mkdir -p /home/dev/.cache/go-build /home/dev/go/pkg/mod

WORKDIR /src
HEALTHCHECK NONE
