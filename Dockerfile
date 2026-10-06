# syntax=docker/dockerfile:1.7
# scanX server/worker/CLI image: static binary on distroless, non-root.

FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-buildvcs=false
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath \
      -ldflags "-s -w -X github.com/ininia/scanx/internal/version.Version=${VERSION} -X github.com/ininia/scanx/internal/version.Commit=${COMMIT} -X github.com/ininia/scanx/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -o /out/scanx ./cmd/scanx

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="scanX" \
      org.opencontainers.image.source="https://github.com/ininia/scanx" \
      org.opencontainers.image.licenses="BUSL-1.1"
COPY --from=build /out/scanx /scanx
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD ["/scanx", "healthcheck"]
ENTRYPOINT ["/scanx"]
CMD ["server"]
