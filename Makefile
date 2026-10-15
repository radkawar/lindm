.PHONY: bootstrap tools generate generate-code web-assets lint fmt audit check build test test-integration dev-up dev-down dev-check dev-trust
.DEFAULT_GOAL := check

export GOTOOLCHAIN := go1.26.9
# Every recipe runs the pinned Node (.node-version) and Go (go.mod) first on
# PATH, whatever the caller's shell puts first (a mise global Node 26 broke
# the console review); a stale GOROOT would pair a go with another release's
# standard library. A pinned version that is missing stops make here.
TOOLCHAIN_PATH := $(shell env -u GOROOT go run ./cmd/dev toolchain-path)
ifeq ($(strip $(TOOLCHAIN_PATH)),)
$(error pinned toolchains unavailable; see the error above (go run ./cmd/dev toolchain-path))
endif
export PATH := $(TOOLCHAIN_PATH)
unexport GOROOT
TOOLS := $(CURDIR)/.tools/bin
BUF := $(TOOLS)/buf
SQLC := $(TOOLS)/sqlc
GOLANGCI := $(TOOLS)/golangci-lint
GOVULNCHECK := $(TOOLS)/govulncheck
GO_DIRS := cmd db gen internal web
GO_PACKAGES := $(addsuffix /...,$(addprefix ./,$(GO_DIRS)))
# Clean-worktree gates pass --allow-parallel-runners with their own cache.
GOLANGCI_RUN_FLAGS ?=

.PHONY: release-keys release
RELEASE_KEYS_ARGS ?=
RELEASE_ARGS ?=
OFFLINE ?=

release-keys:
	mkdir -p artifacts/bin
	go build -o artifacts/bin/release ./cmd/release
	./artifacts/bin/release init $(RELEASE_KEYS_ARGS)

release: generate-licenses
	mkdir -p artifacts/bin
	go build -o artifacts/bin/release ./cmd/release
	./artifacts/bin/release build --offline "$(OFFLINE)" $(RELEASE_ARGS)

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
	GOBIN="$(TOOLS)" go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
	@touch "$@"

$(TOOLS)/protoc-gen-go: Makefile
	GOBIN="$(TOOLS)" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	@touch "$@"

$(TOOLS)/protoc-gen-connect-go: Makefile
	GOBIN="$(TOOLS)" go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.1
	@touch "$@"

bootstrap: tools
	npm ci --ignore-scripts
	npm run hooks:install

# Both fail in the shared main checkout by design: its tracked files are
# read-only outside landings (go run ./cmd/dev protect). Generate in a private
# worktree and land; dev land reruns generate-code (the buf/sqlc part) under
# the landing lock, so generated output derives from main plus the landing.
generate: generate-code
	$(MAKE) generate-licenses
	go run ./cmd/devenv generate-docs

generate-code: $(BUF) $(SQLC) $(TOOLS)/protoc-gen-go $(TOOLS)/protoc-gen-connect-go
	@test -w go.mod || { echo "make generate: tracked files here are read-only (the protected shared checkout); generate in a private worktree and land the output" >&2; exit 1; }
	$(BUF) generate
	$(SQLC) generate
	node internal/agent/desktop/keysymdata/generate.mjs
	node test/tooling/license-headers.mjs generated

.PHONY: generate-licenses
generate-licenses: web-assets
	node test/tooling/generate-license-notices.mjs

web-assets:
	npm run build:web

lint: web-assets $(BUF) $(GOLANGCI)
	npm run check
	$(BUF) lint
	$(BUF) format --diff --exit-code
	$(GOLANGCI) run $(GOLANGCI_RUN_FLAGS) $(GO_PACKAGES)
	@diff="$$($(GOLANGCI) fmt --diff $(GO_DIRS))" && { test -z "$$diff" || { printf '%s\n' "$$diff"; exit 1; }; }
	go run ./cmd/devenv generate-docs -check

fmt: $(BUF) $(GOLANGCI)
	npm run format
	$(BUF) format -w
	$(GOLANGCI) fmt $(GO_DIRS)

audit: web-assets $(GOVULNCHECK)
	npm run audit:dependencies
	$(GOVULNCHECK) $(GO_PACKAGES)

# Each test binary gets the integration lock's 45m budget (cmd/devenv
# integrationLockCap), as in the land gate: loaded hosts push the
# internal/agent/executor race suite past go test's 10m default.
test: web-assets
	node --test test/tooling/check-dco.test.mjs test/tooling/enrollment-snippets.test.mjs web/acceptance/assistance-input.test.mjs web/acceptance/assistance-presentation.test.mjs web/acceptance/assistance-marker.test.mjs web/acceptance/mcp-http.test.mjs web/acceptance/assistance-annotation.test.mjs web/acceptance/assistance-overlay.test.mjs web/acceptance/assistance-capability-modes.test.mjs
	node --experimental-transform-types --test web/acceptance/assistance-files.test.mjs web/acceptance/assistance-recording.test.mjs
	go test -race -timeout 45m $(GO_PACKAGES)
	node --test web/acceptance/assistance-startup.test.mjs web/acceptance/assistance-end.test.mjs web/acceptance/journey.test.mjs web/acceptance/review-edit-sheet.test.mjs web/acceptance/review-contrast.test.mjs web/acceptance/patch-status-copy.test.mjs web/eslint/freeform-input.test.mjs web/eslint/no-raw-colours.test.mjs web/eslint/scan-css-colours.test.mjs

build: web-assets
	go build -trimpath -o artifacts/bin/lindmd ./cmd/lindmd
	go build -trimpath -o artifacts/bin/lindm-agent ./cmd/lindm-agent
	go build -trimpath -o artifacts/bin/lab ./cmd/lab

check: lint test audit

test-integration: dev-up
	go run ./cmd/devenv test-integration

dev-up: web-assets
	go run ./cmd/devenv up

dev-down:
	go run ./cmd/devenv down

dev-check:
	go run ./cmd/devenv check

dev-trust:
	go run ./cmd/devenv trust

.PHONY: acceptance check-web acceptance-build browser-baseline ui-review
ACCEPTANCE_EVIDENCE ?= $(CURDIR)/artifacts/acceptance-$(shell date -u +%Y%m%dT%H%M%SZ)
ACCEPTANCE_FLAGS ?=
BROWSER_BASELINE_RECORD ?= $(CURDIR)/artifacts/browser-baseline-$(shell date -u +%Y%m%dT%H%M%SZ).json
UI_REVIEW_EVIDENCE ?= $(CURDIR)/artifacts/ui-review-$(shell date -u +%Y%m%dT%H%M%SZ)
UI_REVIEW_REPO ?= .
UI_REVIEW_FLAGS ?=

acceptance-build: web-assets
	go build -trimpath -ldflags '-X lindm/internal/agent/buildinfo.Version=0.1.0 -X lindm/internal/agent/buildinfo.Revision=console-enrollment-lab' -o artifacts/bin/lindmd ./cmd/lindmd
	CGO_ENABLED=0 go build -trimpath -o artifacts/bin/lab ./cmd/lab

# Browser drivers are explicit prerequisites, never silently substituted engines.
browser-baseline:
	go run ./cmd/lab hosts baseline-browser -record "$(BROWSER_BASELINE_RECORD)"
	./node_modules/.bin/playwright install chromium

check-web: acceptance-build
	node --test test/tooling/enrollment-snippets.test.mjs web/acceptance/deploy-actions.test.mjs web/acceptance/deploy-browser.test.mjs
	artifacts/bin/lab acceptance -web-only -evidence "$(ACCEPTANCE_EVIDENCE)" $(ACCEPTANCE_FLAGS)

acceptance: acceptance-build
	artifacts/bin/lab acceptance -evidence "$(ACCEPTANCE_EVIDENCE)" $(ACCEPTANCE_FLAGS)

ui-review: acceptance-build
	node --test web/acceptance/review-ste.test.mjs web/acceptance/review-help.test.mjs web/acceptance/review-contrast.test.mjs web/acceptance/review-capture.test.mjs web/acceptance/patch-status-copy.test.mjs
	artifacts/bin/lab console review -repo "$(UI_REVIEW_REPO)" -lindmd artifacts/bin/lindmd -evidence "$(UI_REVIEW_EVIDENCE)" $(UI_REVIEW_FLAGS)

# Local CI (basecamp/gh-signoff): cmd/devenv signoff refuses an unpushed HEAD,
# runs the gates in a temporary clean worktree of that SHA (integration and
# acceptance against this checkout's dev fixture), then posts green statuses
# with gh signoff create --commit SHA, so a signoff attests to exactly what is
# on GitHub even while this tree is dirty. Contexts: unit (make check),
# integration (real PostgreSQL) and acceptance.
.PHONY: signoff signoff-acceptance pre-push
signoff: dev-up
	go run ./cmd/devenv signoff

signoff-acceptance:
	go run ./cmd/devenv signoff -acceptance -acceptance-flags "$(ACCEPTANCE_FLAGS)"

# Git pre-push hook body: make check at each pushed SHA in a clean worktree,
# skipped when that SHA already carries a green signoff/unit.
pre-push:
	go run ./cmd/devenv pre-push

