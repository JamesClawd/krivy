# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Krivy privately through GitHub's
[private vulnerability reporting](https://github.com/l4r-s/krivy/security/advisories/new)
(repository **Security** tab → **Report a vulnerability**). Do not open a
public issue, pull request or discussion for a suspected vulnerability.

Include:

* the Krivy version (`krivy --version` or the image tag) and how it is
  deployed (Helm chart version, database driver);
* the affected component (REST API, MCP, webhooks, scanner Jobs, chart, …);
* steps to reproduce or a proof of concept, and the impact you expect.

You should get an acknowledgement within a few days. Fixes are released as a
new patch version and announced through a GitHub security advisory, crediting
the reporter unless you prefer otherwise.

## Supported versions

Krivy is pre-1.0. Security fixes go into the latest release only.

## Scope

In scope: the Krivy controller, its container image, the Helm chart and the
scanner Job specification it generates.

Out of scope: vulnerabilities that Krivy *reports* in your images (those
belong to the respective image or package maintainers), and vulnerabilities in
Trivy itself (report those to [Aqua Security](https://github.com/aquasecurity/trivy/security)).

How Krivy is designed to be safe to run is described in
[docs/security-model.md](docs/security-model.md).
