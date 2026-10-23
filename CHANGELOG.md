# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release.

### Added

- Kubernetes controller that discovers images of running and pending Pods
  (containers, init and ephemeral containers) with read-only RBAC and resolves
  owners to Deployment, CronJob, StatefulSet, DaemonSet, Job or Pod.
- Image deduplication by running digest, with tag fallback and Docker Hub
  name normalization.
- One ephemeral, hardened Trivy Job per image: no PersistentVolume, no
  ServiceAccount token, non-root, read-only root filesystem, bounded
  `emptyDir`, deadline and TTL. Default Trivy image
  `ghcr.io/aquasecurity/trivy:0.67.2`, `CRITICAL` severity by default.
- Persistent scan queue with request deduplication, bounded concurrency,
  per-image retries with failure classification, cancellation and restart
  recovery that re-attaches to running Jobs.
- Scheduler (default `@every 12h`, `off` to disable) anchored at the last
  cluster scan, with optional scan on first startup.
- Findings with stable IDs, automatic resolution (`fixed`, `not_deployed`)
  and reopening.
- Acknowledgements and silences by finding, image (digest or whole
  repository), namespace and vulnerability.
- REST API under `/api/v1` with an embedded OpenAPI 3.1 document.
- MCP server (Streamable HTTP) at `/mcp` with read, scan and triage tools.
- Static bearer tokens with `read`, `scan` and `manage` scopes, stored as
  SHA-256 hashes and compared in constant time.
- Webhook notifications (`new_critical`, `resolved`, `scan_failed`) with Go
  templates, examples for Telegram, Discord, Slack and generic JSON, SSRF
  protection, retries with backoff and delivery dedupe.
- SQLite and PostgreSQL storage with automatic migrations.
- YAML configuration with `${ENV}` substitution and `--check-config`.
- Helm chart published to `oci://ghcr.io/l4r-s/charts/krivy`, multi-arch
  container image `ghcr.io/l4r-s/krivy`.
- Local k3d development cluster and integration tests.

[Unreleased]: https://github.com/l4r-s/krivy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/l4r-s/krivy/releases/tag/v0.1.0
