.PHONY: bootstrap tools generate web-assets lint fmt audit check build test test-integration dev-up dev-down dev-check dev-trust
.DEFAULT_GOAL := check

export GOTOOLCHAIN := go1.26.9
TOOLS := $(CURDIR)/.tools/bin
BUF := $(TOOLS)/buf
SQLC := $(TOOLS)/sqlc
GOLANGCI := $(TOOLS)/golangci-lint
GOVULNCHECK := $(TOOLS)/govulncheck
GO_DIRS := cmd db gen internal web
GO_PACKAGES := $(addsuffix /...,$(addprefix ./,$(GO_DIRS)))

tools: $(BUF) $(SQLC) $(GOLANGCI) $(GOVULNCHECK) $(TOOLS)/protoc-gen-go $(TOOLS)/protoc-gen-connect-go

$(BUF): Makefile
	GOBIN="$(TOOLS)" go install github.com/bufbuild/buf/cmd/buf@v1.73.0
	@touch "$@"

$(SQLC): Makefile
	GOBIN="$(TOOLS)" go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
	@touch "$@"

$(GOLANGCI): Makefile
	GOBIN="$(TOOLS)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
	@touch "$@"

$(GOVULNCHECK): Makefile
	GOBIN="$(TOOLS)" go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
	@touch "$@"

$(TOOLS)/protoc-gen-go: Makefile
	GOBIN="$(TOOLS)" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	@touch "$@"

$(TOOLS)/protoc-gen-connect-go: Makefile
	GOBIN="$(TOOLS)" go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.0
	@touch "$@"

bootstrap: tools
	npm ci --ignore-scripts
	npm run hooks:install

generate: $(BUF) $(SQLC) $(TOOLS)/protoc-gen-go $(TOOLS)/protoc-gen-connect-go
	$(BUF) generate
	$(SQLC) generate

web-assets:
	npm run build:web

lint: web-assets $(BUF) $(GOLANGCI)
	npm run check
	$(BUF) lint
	$(BUF) format --diff --exit-code
	$(GOLANGCI) run $(GO_PACKAGES)
	@diff="$$($(GOLANGCI) fmt --diff $(GO_DIRS))" && { test -z "$$diff" || { printf '%s\n' "$$diff"; exit 1; }; }

fmt: $(BUF) $(GOLANGCI)
	npm run format
	$(BUF) format -w
	$(GOLANGCI) fmt $(GO_DIRS)

audit: web-assets $(GOVULNCHECK)
	npm run audit:dependencies
	$(GOVULNCHECK) $(GO_PACKAGES)

test: web-assets
	go test -race $(GO_PACKAGES)

build: web-assets
	go build -trimpath -o artifacts/bin/lindmd ./cmd/lindmd
	go build -trimpath -o artifacts/bin/lindm-agent ./cmd/lindm-agent
	go build -trimpath -o artifacts/bin/lab ./cmd/lab

check: lint test audit

test-integration: dev-up
	go run ./cmd/dev test-integration

dev-up: web-assets
	go run ./cmd/dev up

dev-down:
	go run ./cmd/dev down

dev-check:
	go run ./cmd/dev check

dev-trust:
	go run ./cmd/dev trust
