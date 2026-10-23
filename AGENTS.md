# AGENTS.md

Guide for coding agents working on Krivy, a Go Kubernetes controller that
scans running images with one ephemeral Trivy Job per image and serves REST,
MCP and webhooks. Module: `github.com/l4r-s/krivy`. Go version: see `go.mod`.
User docs: [README.md](README.md), [docs/](docs/). Architecture:
[docs/architecture.md](docs/architecture.md).

## Layout and contracts

| Path | Contract |
|---|---|
| `cmd/krivy` | Wiring only: load config, open store, build client, start orchestrator, scheduler, notifier and HTTP server. Flags `--config`, `--check-config`, `--version`. |
| `internal/config` | `Load` = strict YAML → `${ENV}` expansion (only DSN, token, sha256, webhook url/headers/secrets) → env overrides → defaults → `Validate`. Unset variables are an error. Templates are never expanded. |
| `internal/kube` | Client from in-cluster config, or kubeconfig **plus a mandatory explicit context**. |
| `internal/discovery` | `Discoverer.Discover(ctx, ns)`; read-only (list pods, get replicasets/jobs). Returns images keyed `repo@digest` (or normalized tag ref) with their workloads. |
| `internal/scanner` | `Scanner.Scan(ctx, Target)` blocks until done. `BuildJob` must never add a PVC or mount a SA token. Errors are `*scanner.Error` with `Kind` and `Retryable`. Deletes the Job only when `context.Cause(ctx) == ErrScanCancelled`; on shutdown it leaves Jobs running for re-attach. `Fake` is the test double. |
| `internal/orchestrator` | Persistent queue: one run at a time, `maxConcurrentJobs` images in parallel, dedupe in `Enqueue`, `Cancel`, `recover` on start. `Scheduler` anchors at the latest cluster run. |
| `internal/findings` | `ReconcileImage` (only for successful scans, only that image's findings), `ResolveUndeployed`, stable `ID`, `Policy` (ack/silence rules). |
| `internal/store` | `Store` interface + GORM implementation for sqlite/postgres, migrations in `migrate.go`. `storetest.ForEachDriver` runs a test on SQLite and, if configured, PostgreSQL. |
| `internal/service` | `service.API`: the only business layer used by REST and MCP. Every method enforces its scope with `auth.Require`. |
| `internal/auth` | Static tokens, SHA-256 hashed, constant-time compare. `read` < `scan` < `manage`. |
| `internal/api` | REST handlers; `routeTable()` is the source of truth; `openapi.yaml` is embedded and served. |
| `internal/mcpserver` | MCP tools over Streamable HTTP, same tokens, same `service.API`. |
| `internal/notify` | `Notifier.Notify(ctx, Event)` records + enqueues; workers render, send, retry. SSRF guard in `ssrf.go`. |
| `internal/httpserver` | Root mux and security headers. |
| `charts/krivy` | Helm chart; `values.schema.json` and the chart README must match `values.yaml`. |
| `hack/` | `dev-cluster.sh` (k3d), `chart-test.sh`, dev config and seed in `hack/dev/`. |
| `test/integration` | Build tag `integration`; runs against the k3d dev cluster. |

Dependency direction: `api`/`mcpserver` → `service` → `orchestrator`/`findings`/`store`.
Do not call the store or orchestrator directly from transport packages.

## Tests

```sh
make test          # unit tests; no Docker, no cluster, no network
make test-race     # what CI runs
make lint          # go vet + golangci-lint v2 if installed
```

* Unit tests use fake clientsets, `scanner.Fake`, Trivy JSON fixtures in
  `internal/scanner/testdata`, and SQLite in `t.TempDir()`. Keep them
  hermetic: never download the Trivy DB or reach the network.
* PostgreSQL store tests: start a Postgres and run
  `KRIVY_TEST_POSTGRES_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' make test-postgres`.
  Each test gets a fresh schema that is dropped afterwards. Without the
  variable these tests run on SQLite only.
* Integration tests against k3d:
  ```sh
  make dev-cluster dev-seed test-integration
  ```
  They use **only** `.dev/kubeconfig` with context `k3d-krivy-dev` and refuse
  any other context. `KRIVY_INTEGRATION=1` is required (the make target sets
  it); `KRIVY_INTEGRATION_REAL_TRIVY=1` additionally runs a real Trivy scan
  (network, ~1 GiB RAM). Run the controller against the dev cluster with
  `make dev-run`; details in [docs/development.md](docs/development.md).
* Chart: `make chart-lint chart-test`.

## Gotchas

* **Never commit `.dev/`** (kubeconfig, SQLite DB). It is gitignored; keep it
  that way. Never point tooling at `~/.kube/config`.
* `scanner.Config.Command` overrides the container entrypoint for
  integration tests only (stub scanner image). Do not expose it in the YAML
  config or the chart.
* **Keep `internal/api/openapi.yaml` in sync** with `routeTable()`.
  `TestOpenAPI` fails when a route is missing from the spec or its
  `security` does not match the route's scope. Update `docs/api.md` too, and
  `docs/mcp.md` if an MCP tool changes.
* **CI gate:** the `mandatory-checks` job ("Mandatory checks") in
  `.github/workflows/ci.yml` is the required check. When you add a CI job,
  add it to that job's `needs:` list, otherwise it is not enforced.
* Config keys are parsed strictly; adding one means updating
  `internal/config`, the chart (`values.yaml`, `values.schema.json`,
  `_helpers.tpl` config rendering, chart README) and
  `docs/configuration.md`.
* Secrets must reach webhook templates only via `.Secrets`; do not add env
  expansion to templates.
* Diagnostics and delivery errors are user-visible; run new error text through
  the existing redaction (`scanner.redact`, `destination.redact`).
* Single replica by design: do not add code that assumes multiple controllers.
* Commits use Conventional Commits; see [CONTRIBUTING.md](CONTRIBUTING.md).
