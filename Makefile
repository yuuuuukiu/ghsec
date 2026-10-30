BINARY      := ghsec
CMD         := ./cmd/ghsec
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIST        := dist

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

GOBIN_TARGETS := \
	$(DIST)/$(BINARY)-darwin-arm64 \
	$(DIST)/$(BINARY)-darwin-amd64 \
	$(DIST)/$(BINARY)-linux-amd64 \
	$(DIST)/$(BINARY)-linux-arm64 \
	$(DIST)/$(BINARY)-windows-amd64.exe \
	$(DIST)/$(BINARY)-windows-arm64.exe

.PHONY: all build run test test-race vet fmt lint check clean tidy build-all checksums size e2e accept help

all: check build

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary for the host platform
	@mkdir -p $(DIST)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY) $(CMD)
	@echo "built $(DIST)/$(BINARY)"

run: ## Run ghsec from source
	go run $(CMD)

test: ## Run the unit test suite
	go test ./... -count=1

test-race: ## Run the unit test suite with the race detector
	go test ./... -race -count=1

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go sources
	gofmt -l -w .

lint: ## Fail if any file is unformatted or vet reports an issue
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi
	go vet ./...

check: lint test ## Lint + test

tidy: ## Tidy go.mod / go.sum
	go mod tidy

build-all: ## Cross-compile every release target
	@mkdir -p $(DIST)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-arm64      $(CMD)
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-amd64      $(CMD)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64       $(CMD)
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64       $(CMD)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-amd64.exe $(CMD)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-arm64.exe $(CMD)
	@echo "cross-compiled $(words $(GOBIN_TARGETS)) targets into $(DIST)/"

e2e: build ## Run the PTY-driven end-to-end acceptance suite
	@python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
		|| { echo "python3 >= 3.9 is required for the e2e suite"; exit 1; }
	python3 scripts/e2e.py $(DIST)/$(BINARY)

accept: check build-all size e2e ## Full acceptance run (lint, tests, cross-compile, size, e2e)
	@echo
	@echo "acceptance complete: unit tests, 6 cross-compiled targets, size budget, e2e"

size: build-all ## Report sizes and enforce the ~15 MB budget
	@bash scripts/check-size.sh $(DIST)

checksums: build-all ## Write SHA256SUMS for release artefacts
	@cd $(DIST) && sha256sum $(notdir $(GOBIN_TARGETS)) > SHA256SUMS && cat SHA256SUMS

clean: ## Remove build artefacts
	rm -rf $(DIST)
