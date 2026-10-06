# scanX Makefile. On machines without Go/make use: scripts/dev.sh <target>
SHELL := /bin/sh
GO    ?= go
TESTFLAGS ?=
PKG   := github.com/ininia/scanx
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
IMAGE   ?= ghcr.io/ininia/scanx
COMPOSE := docker compose -f deploy/docker-compose.yml --env-file deploy/.env

.PHONY: all fmt lint vet test test-integration cover build images up down logs tidy

all: lint test build

fmt:
	gofumpt -w .

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

test:
	CGO_ENABLED=1 $(GO) test -race -count=1 -cover $(TESTFLAGS) ./...

# Requires SCANX_TEST_DATABASE_ADMIN_URL and SCANX_TEST_DATABASE_URL
# (scripts/dev.sh test-integration starts a throwaway PostgreSQL).
test-integration:
	@test -n "$$SCANX_TEST_DATABASE_URL" || (echo "SCANX_TEST_DATABASE_URL not set" && exit 1)
	$(GO) test -tags integration -count=1 -p 1 $(TESTFLAGS) ./...

cover:
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/scanx ./cmd/scanx

tidy:
	$(GO) mod tidy

images:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE):$(VERSION) .

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200
