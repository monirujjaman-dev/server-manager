# Server Manager — developer tasks. Run `make help` for a list.

GO          ?= go
TOOL        := $(GO) tool -modfile=tools/go.mod
BIN         ?= bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := github.com/monirujjaman-dev/server-manager/internal/pkg/version
LDFLAGS     := -s -w -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).Date=$(DATE)
GOLANGCI    ?= golangci-lint
COMPOSE     ?= docker compose -f deploy/compose/dev.yaml
DEV_DB_URL  ?= postgres://sm:sm-dev-only@127.0.0.1:5432/sm?sslmode=disable
DEV_DIR     ?= .dev

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build sm-server, sm-agent and smctl into ./bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...

.PHONY: test
test: ## Run unit and integration tests (set SM_TEST_DATABASE_URL for store tests)
	$(GO) test -race -count=1 ./...

.PHONY: lint
lint: ## Run golangci-lint and buf lint
	$(GOLANGCI) run ./...
	$(TOOL) buf lint

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities
	$(TOOL) govulncheck ./...

.PHONY: generate
generate: ## Regenerate protobuf and sqlc code
	$(TOOL) buf generate
	$(TOOL) sqlc generate

.PHONY: check-generated
check-generated: generate ## Fail if generated code is out of date
	git diff --exit-code -- gen internal/server/store/db

.PHONY: dev-up
dev-up: ## Start PostgreSQL and VictoriaMetrics for development
	$(COMPOSE) up -d --wait

.PHONY: dev-down
dev-down: ## Stop the development services
	$(COMPOSE) down

.PHONY: dev-migrate
dev-migrate: build ## Apply migrations to the development database
	SM_DATABASE_URL='$(DEV_DB_URL)' $(BIN)/sm-server migrate up

.PHONY: dev-pki
dev-pki: build ## Create a dev CA, server cert and one enrolled agent in ./.dev
	$(BIN)/sm-server pki init --dir $(DEV_DIR)/pki --dns localhost --ip 127.0.0.1
	$(BIN)/sm-agent keygen --dir $(DEV_DIR)/agent
	$(BIN)/sm-server pki sign-agent --dir $(DEV_DIR)/pki --csr $(DEV_DIR)/agent/agent.csr --out $(DEV_DIR)/agent/agent.crt
	cp $(DEV_DIR)/pki/root.crt $(DEV_DIR)/agent/ca.crt

.PHONY: dev-server
dev-server: build ## Run the control plane with the dev config
	$(BIN)/sm-server serve --config deploy/dev/sm-server.yaml

.PHONY: dev-agent
dev-agent: build ## Run an agent against the local control plane
	$(BIN)/sm-agent run --config deploy/dev/sm-agent.yaml

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN)
