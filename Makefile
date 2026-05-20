SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
HELM          ?= helm
KUBECTL       ?= kubectl
KIND          ?= kind
DOCKER        ?= docker

BIN_DIR       := bin
BIN           := $(BIN_DIR)/dne
IMG           ?= ghcr.io/dgamo/dne:dev
PLATFORMS     ?= linux/amd64,linux/arm64

CHART_DIR     := deploy/helm/dne
CHART_FILES   := $(CHART_DIR)/files
DASH_SRC      := deploy/grafana/dne.json
DASH_DST      := $(CHART_FILES)/dne-dashboard.json
RULES_SRC     := deploy/prometheus/dne-rules.yaml
RULES_DST     := $(CHART_FILES)/dne-rules.yaml

ENVTEST_K8S_VERSION ?= 1.32.0

.PHONY: all
all: lint test build

.PHONY: build
build: ## Build the dne binary
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/dne

.PHONY: test
test: envtest ## Run unit + integration tests with race detector
	KUBEBUILDER_ASSETS="$$($(LOCALBIN)/setup-envtest use $(ENVTEST_K8S_VERSION) -p path)" \
	$(GO) test ./... -race -count=1 -coverprofile=coverage.out

.PHONY: test-unit
test-unit: ## Run unit tests only (skip envtest-dependent packages)
	$(GO) test ./internal/cert/... ./internal/metrics/... ./internal/config/... -race -count=1

.PHONY: cover
cover: test ## Open coverage report in browser
	$(GO) tool cover -html=coverage.out

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run --timeout 5m

.PHONY: fmt
fmt: ## Format Go source
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: docker
docker: ## Build a single-arch container image (use IMG=...)
	$(DOCKER) build -t $(IMG) .

.PHONY: docker-buildx
docker-buildx: ## Build a multi-arch container image with buildx
	$(DOCKER) buildx build --platform $(PLATFORMS) -t $(IMG) .

.PHONY: helm-sync
helm-sync: $(DASH_DST) $(RULES_DST) ## Copy dashboard + rules into the chart so .Files.Get resolves
$(DASH_DST): $(DASH_SRC)
	@mkdir -p $(CHART_FILES)
	cp $< $@
$(RULES_DST): $(RULES_SRC)
	@mkdir -p $(CHART_FILES)
	cp $< $@

.PHONY: helm-sync-check
helm-sync-check: helm-sync ## Fail if the chart-bundled copies have drifted from the sources
	@git diff --exit-code -- $(DASH_DST) $(RULES_DST) || \
		(echo "ERROR: deploy/helm/dne/files/ is out of sync with deploy/grafana/ and deploy/prometheus/. Run 'make helm-sync' and commit." && exit 1)

.PHONY: helm-lint
helm-lint: helm-sync ## helm lint and several template combinations
	$(HELM) lint $(CHART_DIR)
	$(HELM) template dne $(CHART_DIR) > /dev/null
	$(HELM) template dne $(CHART_DIR) --set 'namespaces={kube-system,default}' > /dev/null
	$(HELM) template dne $(CHART_DIR) --set 'labelSelector=dne.k8s.io/watch=true' > /dev/null
	$(HELM) template dne $(CHART_DIR) --set serviceMonitor.enabled=true --set prometheusRule.enabled=true --set grafanaDashboard.enabled=true > /dev/null

.PHONY: helm-package
helm-package: helm-sync ## Package the chart into a .tgz
	$(HELM) package $(CHART_DIR) -d dist/

.PHONY: kind-up
kind-up: ## Spin up a local kind cluster (named dne-test)
	$(KIND) create cluster --name dne-test

.PHONY: kind-down
kind-down: ## Tear down the kind cluster
	$(KIND) delete cluster --name dne-test

.PHONY: kind-load
kind-load: docker ## Build image and load it into the kind cluster
	$(KIND) load docker-image $(IMG) --name dne-test

LOCALBIN := $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

SETUP_ENVTEST_VERSION ?= release-0.24
.PHONY: envtest
envtest: $(LOCALBIN) ## Download setup-envtest + matching kube binaries
	@test -x $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)
	@$(LOCALBIN)/setup-envtest use $(ENVTEST_K8S_VERSION) -p path > /dev/null

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) dist coverage.out coverage.html

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
