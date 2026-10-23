# Krivy — see docs/development.md
SHELL := /bin/sh
GO ?= go
BIN := bin/krivy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/l4r-s/krivy/internal/version.Version=$(VERSION) -X github.com/l4r-s/krivy/internal/version.Commit=$(COMMIT)
IMAGE ?= ghcr.io/l4r-s/krivy:dev

.PHONY: all build run test test-race test-postgres test-integration lint fmt vet docker chart-lint chart-template chart-test clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/krivy

run:
	$(GO) run ./cmd/krivy --config $${KRIVY_CONFIG:-hack/dev/krivy.yaml}

# Unit tests: no Docker or Kubernetes required.
test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Store tests against PostgreSQL; needs KRIVY_TEST_POSTGRES_DSN.
test-postgres:
	$(GO) test ./internal/store/... -run . -count=1

# Integration tests against the k3d dev cluster (make dev-cluster dev-seed first).
# Set KRIVY_INTEGRATION_REAL_TRIVY=1 to also run a real Trivy scan.
test-integration:
	sh hack/dev-cluster.sh check-context
	KRIVY_INTEGRATION=1 $(GO) test -tags integration -count=1 -timeout 20m ./test/integration/...

fmt:
	gofmt -s -w .

vet:
	$(GO) vet ./...

lint: vet
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; ran go vet only"

# The Dockerfile uses BuildKit features (cache mounts, BUILDPLATFORM).
docker:
	DOCKER_BUILDKIT=1 docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

chart-lint:
	helm lint charts/krivy
	for f in charts/krivy/ci/*.yaml; do helm lint charts/krivy -f "$$f" || exit 1; done

chart-test:
	sh hack/chart-test.sh

chart-template:
	helm template krivy charts/krivy >/dev/null

clean:
	rm -rf bin dist coverage.out

# --- local k3d development cluster (see docs/development.md) ---
.PHONY: dev-cluster dev-seed dev-status dev-stop dev-start dev-destroy dev-run dev-kubeconfig
dev-cluster:
	sh hack/dev-cluster.sh create
dev-seed:
	sh hack/dev-cluster.sh seed
dev-status:
	sh hack/dev-cluster.sh status
dev-stop:
	sh hack/dev-cluster.sh stop
dev-start:
	sh hack/dev-cluster.sh start
dev-destroy:
	sh hack/dev-cluster.sh destroy
dev-kubeconfig:
	sh hack/dev-cluster.sh kubeconfig
dev-run:
	sh hack/dev-cluster.sh check-context
	KRIVY_KUBECONFIG=$$(sh hack/dev-cluster.sh kubeconfig-path) KRIVY_KUBE_CONTEXT=k3d-krivy-dev $(GO) run ./cmd/krivy --config hack/dev/krivy.yaml
