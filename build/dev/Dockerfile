# scanX development image: Go toolchain + make + linters.
# Used by scripts/dev.sh so contributors only need Docker (ADR-004).
FROM golang:1.27-alpine

RUN apk add --no-cache make git bash ca-certificates docker-cli build-base

ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false

# Linters are built with the same Go version so they understand go1.27 code.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest \
 && go install mvdan.cc/gofumpt@latest \
 && rm -rf /root/.cache/go-build /go/pkg/mod

WORKDIR /src
