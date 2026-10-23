# Contributing to Krivy

Thanks for your interest. Bug reports, fixes and focused features are welcome.
For larger changes, open an issue first so we can agree on the approach.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.

## Development setup

Everything you need (prerequisites, the local k3d cluster, running Krivy
against it, troubleshooting) is in [docs/development.md](docs/development.md).
Unit tests need only Go; no Docker or cluster.

```sh
make test                                 # unit tests
make dev-cluster dev-seed test-integration   # end-to-end against k3d
```

Coding agents should also read [AGENTS.md](AGENTS.md).

## Make targets

| Target | Purpose |
|---|---|
| `make build` | Static binary in `bin/krivy` |
| `make test` / `make test-race` | Unit tests (CI runs with `-race`) |
| `make test-postgres` | Store tests against PostgreSQL; set `KRIVY_TEST_POSTGRES_DSN` |
| `make test-integration` | Integration tests against the k3d dev cluster; `KRIVY_INTEGRATION_REAL_TRIVY=1` adds a real Trivy scan |
| `make fmt` / `make vet` / `make lint` | `gofmt -s`, `go vet`, golangci-lint v2 if installed |
| `make docker` | Build the container image |
| `make chart-lint` / `make chart-test` | Helm lint and chart assertions (`hack/chart-test.sh`) |
| `make dev-*` | Manage the dev cluster (see docs/development.md) |

## Before opening a pull request

* `make fmt test-race lint` pass.
* Chart changes: `make chart-lint chart-test` pass, and `values.yaml`,
  `values.schema.json` and `charts/krivy/README.md` agree.
* REST changes: `internal/api/openapi.yaml` is updated (a test fails
  otherwise), and `docs/api.md` / `docs/mcp.md` reflect the change.
* Config changes: `docs/configuration.md` and the chart are updated.
* User-visible changes have an entry under `## [Unreleased]` in
  [CHANGELOG.md](CHANGELOG.md).
* New behaviour has tests. Unit tests must stay hermetic: fake Kubernetes
  clients and Trivy fixtures, no network.

CI runs Go tests, lint, an image build, chart tests and the k3d integration
tests. The **Mandatory checks** job aggregates them and is the one required
status check.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scanner): mount registry credentials for private images
fix(notify): honour Retry-After on 503
docs: explain namespace silences
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`,
`ci`, `chore`. Mark breaking changes with `!` (`feat(api)!: …`) or a
`BREAKING CHANGE:` footer.

A Developer Certificate of Origin (DCO) sign-off is **not** required.
By contributing you agree that your contribution is licensed under the
[MIT License](LICENSE).

## Release checklist

Maintainers only.

1. Move the `## [Unreleased]` entries in `CHANGELOG.md` to a new
   `## [X.Y.Z]` section, update the compare links, and merge to `main`.
2. Make sure CI on `main` is green.
3. Tag and push:
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
   `.github/workflows/release.yml` then builds and pushes the multi-arch image
   (`linux/amd64`, `linux/arm64`, with provenance and SBOM) as
   `ghcr.io/l4r-s/krivy:{X.Y.Z, X.Y, latest}`, packages the chart with
   `version = appVersion = X.Y.Z`, pushes it to
   `oci://ghcr.io/l4r-s/charts/krivy`, and creates the GitHub release with the
   chart `.tgz` attached. Tags with a `-` suffix (e.g. `v0.2.0-rc.1`) become
   pre-releases and do not move `latest`.
4. **First release only:** GHCR packages are created private. Set both
   `krivy` and `charts/krivy` to public once, and grant the repository write
   access to each package. Steps and verification commands are in
   [docs/installation.md](docs/installation.md#releases-and-package-visibility-maintainers).
5. Verify the published chart installs from OCI in a scratch cluster:
   ```sh
   helm show chart oci://ghcr.io/l4r-s/charts/krivy --version X.Y.Z
   helm install krivy oci://ghcr.io/l4r-s/charts/krivy --version X.Y.Z \
     -n krivy-system --create-namespace
   kubectl -n krivy-system rollout status deploy/krivy
   ```
6. Optional: list the chart on [Artifact Hub](https://artifacthub.io). This
   needs an `artifacthub-repo.yml` pushed to the OCI repository (as the
   `artifacthub.io` tag) and a repository registration on Artifact Hub. Not set
   up yet.
