.DEFAULT_GOAL := help

ICP ?= icp
VESSEL ?= vessel
NPM ?= npm

.PHONY: help deps build build-frontend build-all test test-unit test-local test-e2e test-all network-test network-stop network-local network-stop-local deploy-test deploy-local logs-test dev clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

deps: ## Install Motoko (Vessel) and frontend (npm) dependencies
	$(VESSEL) install
	$(NPM) --prefix frontend install

build: ## Build the Motoko canister with icp-cli
	$(ICP) build key_exchange

build-frontend: ## Build the Vite frontend
	$(NPM) --prefix frontend run build

build-all: build build-frontend ## Build backend and frontend

test: test-unit test-e2e ## Run unit and end-to-end tests

test-unit: ## Run Motoko unit tests through WASI
	./scripts/test.sh

test-local: ## Run the local deployment smoke test
	./scripts/test-local.sh

test-e2e: ## Run the abort/reveal end-to-end protocol test
	./scripts/test-e2e.sh

test-all: test-unit test-local test-e2e ## Run all test targets

network-test: ## Start the local test network on port 18080
	$(ICP) network start test -d

network-stop: ## Stop the local test network
	$(ICP) network stop test

network-local: ## Start the default local network
	$(ICP) network start -d

network-stop-local: ## Stop the default local network
	$(ICP) network stop

deploy-test: ## Deploy the canister to the running test network
	$(ICP) deploy -e test -y

deploy-local: ## Deploy the canister to the default local network
	$(ICP) deploy -y

logs-test: ## Show canister logs from the test network
	$(ICP) canister logs -e test key_exchange

dev: ## Start the Vite frontend dev server
	$(NPM) --prefix frontend run dev

clean: ## Remove generated build and test artifacts
	rm -rf .test .icp frontend/dist frontend/src/bindings
