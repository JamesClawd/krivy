# Development

You can do most Krivy development without Kubernetes: unit tests need no
Docker and no cluster. For end-to-end work there is a disposable local
[k3d](https://k3d.io) cluster called `krivy-dev`. Its credentials go to a
dedicated kubeconfig (`.dev/kubeconfig`), so your `~/.kube/config` and other
clusters are never touched.

## Prerequisites

| Tool | Needed for | macOS | Linux |
|---|---|---|---|
| Go (version in `go.mod`) | everything | `brew install go` or go.dev/dl | go.dev/dl |
| Docker runtime | dev cluster, image build | Docker Desktop, OrbStack, or Colima (`brew install colima docker && colima start --cpu 2 --memory 4`) | Docker Engine (docs.docker.com/engine/install), user in the `docker` group |
| k3d ≥ 5.6 | dev cluster | `brew install k3d` | `curl -fsSL https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| TAG=v5.8.3 bash` |
| kubectl | dev cluster | `brew install kubectl` | kubernetes.io/docs/tasks/tools |
| helm ≥ 3.14 | chart work | `brew install helm` | helm.sh/docs/intro/install |
| golangci-lint v2 (optional) | `make lint` | `brew install golangci-lint` | golangci-lint.run |
| shellcheck (optional) | script linting | `brew install shellcheck` | `apt install shellcheck` |

`hack/dev-cluster.sh` checks for docker, k3d and kubectl, and checks that the
Docker daemon is reachable. If something is missing it prints install
instructions for your OS.

### Resource expectations

* The dev cluster (one k3s server, with traefik, servicelb and metrics-server
  disabled) uses about 500–700 MiB RAM when idle.
* Each Trivy scanner Job requests 100m CPU and 256 MiB, may use up to 1 GiB
  memory, and needs up to 2 GiB of ephemeral storage. The first scan downloads
  the Trivy vulnerability DB (~60–80 MiB compressed). Each scan does this
  because scanner Jobs never use a persistent volume.
* Give the Docker VM at least 2 CPUs and 4 GiB RAM (Colima:
  `colima start --cpu 2 --memory 4`). With `maxConcurrentJobs: 2` in the dev
  config, 4 GiB is enough.
* Scanner pods need internet access to reach ghcr.io / mirror.gcr.io (Trivy DB)
  and the registries of the scanned images.

## Make targets

| Target | What it does |
|---|---|
| `make build` | Static binary in `bin/krivy` (version from `git describe`). |
| `make test` | Unit tests. No Docker or Kubernetes needed. |
| `make test-race` | Unit tests with the race detector (what CI runs). |
| `make test-postgres` | Store tests against PostgreSQL (`KRIVY_TEST_POSTGRES_DSN`). |
| `make lint` / `make fmt` / `make vet` | Static checks / formatting. |
| `make docker` | Build the container image `ghcr.io/l4r-s/krivy:dev` (BuildKit/buildx). |
| `make chart-lint` / `make chart-template` | Helm checks. Run `sh hack/chart-test.sh` for the full chart assertions. |
| `make dev-cluster` | Create (or start) the k3d cluster and write `.dev/kubeconfig`. Idempotent. |
| `make dev-seed` | Apply `hack/dev/seed.yaml`: namespaces `krivy-system`, `production` and `staging`; sample workloads that share images; the `krivy-scanner` ServiceAccount. |
| `make dev-status` | Cluster, node, seeded pod and scanner Job status. |
| `make dev-stop` / `make dev-start` | Stop/start the cluster containers. State is preserved. |
| `make dev-destroy` | Delete the cluster and `.dev/kubeconfig`. `.dev/krivy.db` is kept. |
| `make dev-kubeconfig` | Print `export KUBECONFIG=…/.dev/kubeconfig`. |
| `make dev-run` | Run the controller locally against the dev cluster. |
| `make test-integration` | Integration tests against the dev cluster. |

## Running Krivy against the dev cluster

```sh
make dev-cluster      # ~30s the first time (pulls the k3s image)
make dev-seed
make dev-run          # go run ./cmd/krivy --config hack/dev/krivy.yaml
```

`make dev-run` first runs `hack/dev-cluster.sh check-context`. That check fails
unless `.dev/kubeconfig` exists, its current-context is exactly
`k3d-krivy-dev`, and its API server is a local address. Krivy then gets
`KRIVY_KUBECONFIG` and `KRIVY_KUBE_CONTEXT`, so it can only talk to the dev
cluster. Even if your shell's `KUBECONFIG` points at production, Krivy will
not use it.

The dev configuration (`hack/dev/krivy.yaml`):

* uses SQLite at `.dev/krivy.db` (gitignored);
* creates scanner Jobs in `krivy-system` as `krivy-scanner`;
* sets `scan.schedule: "off"` and `scanOnStartup: false`, so scans run only
  when you trigger them. An omitted or empty schedule falls back to the
  default `@every 12h`;
* sets `maxConcurrentJobs: 2`;
* defines two **insecure, dev-only** tokens that are stored as sha256 hashes,
  so no environment variable is needed:
  * `krivy-dev-read-token-insecure` (scope `read`)
  * `krivy-dev-manage-token-insecure` (scopes `read`, `scan`, `manage`)

```sh
curl -s localhost:8080/healthz
curl -s -H 'Authorization: Bearer krivy-dev-read-token-insecure' localhost:8080/api/v1/summary
curl -s -X POST -H 'Authorization: Bearer krivy-dev-manage-token-insecure' localhost:8080/api/v1/scans
make dev-status       # watch the Trivy Jobs in krivy-system
```

To use kubectl yourself, run `eval "$(make -s dev-kubeconfig)"`, or pass
`--kubeconfig .dev/kubeconfig --context k3d-krivy-dev`.

The config references secrets as `${ENV_VAR}`. Loading fails if a referenced
variable is unset. If you add a webhook such as
`url: "${KRIVY_DEV_WEBHOOK_URL}"`, export the variable first.

### Seed workloads

| Namespace | Workload | Images |
|---|---|---|
| production | Deployment `web` | `busybox:1.36.1` |
| production | CronJob `report` (every 5 min, runs 4 min; `dev-seed` also starts `report-seed` immediately) | `alpine:3.19.1` |
| staging | Deployment `web` | `busybox:1.36.1` |
| staging | Pod `debug` with init container | `alpine:3.19.1` (init), `busybox:1.36.1` |

The same two images are used across namespaces and owners. This exercises
deduplication (one scan per image) and owner resolution
(Deployment / CronJob / bare Pod, plus init containers).

### Optional: k3s version

By default the script uses k3d's default k3s image. To pin one, set:

```sh
KRIVY_DEV_K3S_IMAGE=rancher/k3s:v1.33.4-k3s1 make dev-cluster
```

## Tests

* **Unit tests** (`make test`, `make test-race`) are hermetic. Trivy output
  comes from fixtures and Kubernetes from fake clients.
* **Integration tests** (`make test-integration`) need the seeded dev cluster.
  They run with `-tags integration` and `KRIVY_INTEGRATION=1`. CI runs
  `make dev-cluster dev-seed test-integration` on `ubuntu-latest`.
* **Real Trivy scans** need internet access and take minutes, so they are
  opt-in: run the dev cluster with `make dev-run` and trigger a scan, or run
  `KRIVY_INTEGRATION_REAL_TRIVY=1 make test-integration`.
  Unit tests never download the Trivy DB.

## Helm chart

```sh
helm lint charts/krivy
sh hack/chart-test.sh                     # lint + render + assertions (RBAC, PVCs, security)
helm template krivy charts/krivy -f charts/krivy/ci/postgres-values.yaml | less
```

`hack/chart-test.sh` needs only `helm`. If `kubeconform` is installed, it also
validates the rendered manifests. (`kubectl apply --dry-run=client` still needs
a reachable API server for discovery, so the script does not use it.)

To try the chart in the dev cluster:

```sh
make docker IMAGE=krivy:dev
k3d image import krivy:dev -c krivy-dev
helm --kubeconfig .dev/kubeconfig --kube-context k3d-krivy-dev upgrade --install krivy charts/krivy \
  -n krivy-system --set image.repository=krivy --set image.tag=dev --set image.pullPolicy=Never \
  --set scanner.serviceAccount.create=false   # the seed already created krivy-scanner
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `the Docker daemon is not reachable` | Start Docker Desktop / OrbStack, or run `colima start`. Check `docker context ls`. On Linux, run `sudo systemctl start docker` and check that you are in the `docker` group. |
| `k3d is required but was not found` | Install k3d (see the table above). |
| `current-context … expected 'k3d-krivy-dev'` | `.dev/kubeconfig` was edited or replaced. Run `make dev-cluster` to rewrite it. |
| API server unreachable after a reboot | `make dev-start`. This restarts the containers and refreshes `.dev/kubeconfig` in case the port changed. |
| Port conflict when creating the cluster | k3d picks a random API port. Remove stale clusters with `k3d cluster list` / `make dev-destroy`. |
| Scanner Job stuck `Pending` | Not enough memory or ephemeral storage in the Docker VM. Raise the VM size, or lower `trivy.resources` in `hack/dev/krivy.yaml`. |
| Scan fails with `image_pull` / DB download errors | The scanner pod has no internet access, or a corporate proxy is in the way. Check `kubectl … -n krivy-system logs job/<name>`. |
| `config references unset environment variables` | Export the variables named in the error, or remove the references. |
| Colima: `k3d cluster create` hangs | Use `colima start --network-address` and a recent k3d. Make sure `DOCKER_HOST` matches `docker context inspect`. |
| Start from scratch | `make dev-destroy && rm -f .dev/krivy.db && make dev-cluster dev-seed`. |
