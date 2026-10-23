# Installation

Krivy is distributed as a container image (`ghcr.io/l4r-s/krivy`) and a Helm
chart published as an OCI artifact (`oci://ghcr.io/l4r-s/charts/krivy`).
It requires Kubernetes ≥ 1.27.

## Quick start (SQLite)

```sh
kubectl create namespace krivy-system

# API tokens live in a Secret and reach the config as ${KRIVY_TOKEN_<NAME>}.
kubectl -n krivy-system create secret generic krivy-secrets \
  --from-literal=KRIVY_TOKEN_ADMIN="$(openssl rand -hex 24)" \
  --from-literal=KRIVY_TOKEN_CI="$(openssl rand -hex 24)"

cat > krivy-values.yaml <<'EOF'
existingSecret: krivy-secrets
auth:
  tokens:
    - name: admin          # -> ${KRIVY_TOKEN_ADMIN}
      scopes: [read, scan, manage]
    - name: ci             # -> ${KRIVY_TOKEN_CI}
      scopes: [read, scan]
EOF

helm install krivy oci://ghcr.io/l4r-s/charts/krivy \
  --namespace krivy-system --version 0.1.0 -f krivy-values.yaml
```

Then check it:

```sh
kubectl -n krivy-system port-forward svc/krivy 8080:8080 &
TOKEN=$(kubectl -n krivy-system get secret krivy-secrets -o jsonpath='{.data.KRIVY_TOKEN_ADMIN}' | base64 -d)
curl -s localhost:8080/readyz
curl -s -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/scans
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/summary
```

By default Krivy scans every 12 hours (`scan.schedule: "@every 12h"`). It runs
at most one Trivy Job at a time (`scan.maxConcurrentJobs: 1`) and reports
`CRITICAL` vulnerabilities.

## What runs where

* **Controller** (one replica): discovers images of running Pods (read-only
  RBAC: `pods` get/list/watch; `replicasets`/`jobs` get for owner resolution)
  and serves `/healthz`, `/readyz`, `/api/v1` and `/mcp` on port 8080.
* **Scanner Jobs**: one short-lived `batch/v1` Job per image, created in the
  job namespace (default: the release namespace). The pods run as the
  `krivy-scanner` ServiceAccount. That account has no RBAC bindings and
  `automountServiceAccountToken: false`. Scanner Jobs never use a
  PersistentVolume. The Trivy DB is downloaded into ephemeral storage on each
  scan. In the job namespace the controller can only create/get/list/watch/delete
  Jobs and read pods and pod logs.

The full values reference is in [charts/krivy/README.md](../charts/krivy/README.md).

## Database

### SQLite (default)

```yaml
database:
  driver: sqlite          # DSN defaults to /data/krivy.db
persistence:
  enabled: true           # PVC, 1Gi, ReadWriteOnce
  size: 1Gi
  storageClass: ""        # cluster default
```

* The Deployment uses `strategy: Recreate` so the RWO volume is never mounted
  twice.
* The PVC has `helm.sh/resource-policy: keep` and survives `helm uninstall`.
  Delete it manually if you want to remove the data.
* `persistence.enabled: false` uses an `emptyDir`. All findings are lost when
  the pod restarts. Use this only for evaluation.

### PostgreSQL

```yaml
database:
  driver: postgres        # DSN defaults to "${KRIVY_DATABASE_DSN}"
existingSecret: krivy-secrets
```

```sh
kubectl -n krivy-system create secret generic krivy-secrets \
  --from-literal=KRIVY_DATABASE_DSN='postgres://krivy:PASSWORD@postgres.db.svc:5432/krivy?sslmode=require' \
  --from-literal=KRIVY_TOKEN_ADMIN="$(openssl rand -hex 24)"
```

No PVC is created for PostgreSQL. Krivy runs its schema migrations itself on
startup.

## Tokens and secrets

The ConfigMap only holds `${ENV_VAR}` references. Real values come from
environment variables, which you can provide in three ways:

* `existingSecret: <name>`: every key of that Secret becomes an env var
  (recommended; works with External Secrets / Sealed Secrets).
* `secret.create: true` with `secret.data: {KEY: value}`: the chart manages
  the Secret. Values end up in your Helm release history.
* `extraEnv` / `extraEnvFrom`: any other source.

Each `auth.tokens` entry renders as `token: "${KRIVY_TOKEN_<NAME>}"`. The name
is upper-cased and `-` becomes `_`, so `ci-bot` reads `KRIVY_TOKEN_CI_BOT`.
Use `env:` for a custom variable name. If you only want to store a hash, use
`sha256:` (hex sha256 of the token) instead. Scopes:

| Scope | Allows |
|---|---|
| `read` | Read images, findings, scans |
| `scan` | Trigger scans |
| `manage` | Acknowledge/silence findings and other administrative actions |

Tokens must be at least 16 characters. If a referenced variable is unset,
Krivy refuses to start and logs the variable name. To revoke a token, set
`revoked: true` and run `helm upgrade`. The `checksum/config` annotation
rolls the pod.

## Webhook notifications

`notifications.destinations` is copied into the config unchanged. Templates
are Go templates that Krivy evaluates at send time. Helm does not render them.
Put secrets in `${ENV}` references in `url`, `headers` or `secrets`, never in
the template itself:

```yaml
notifications:
  baseURL: https://krivy.example.com
  destinations:
    - name: slack
      url: "${KRIVY_SLACK_WEBHOOK_URL}"
      events: [new_critical, resolved, scan_failed]
      template: |
        {"text": {{ quote (printf "Krivy %s: %d finding(s)" .Event.Type .Count) }}}
    - name: telegram
      url: "https://api.telegram.org/bot${KRIVY_TELEGRAM_BOT_TOKEN}/sendMessage"
      events: [new_critical]
      namespaces: [production]
      secrets:
        chatID: "${KRIVY_TELEGRAM_CHAT_ID}"
      template: |
        {"chat_id": {{ quote .Secrets.chatID }}, "text": {{ quote (printf "%d new critical CVE(s)" .Count) }}}
```

Add the referenced keys (`KRIVY_SLACK_WEBHOOK_URL`, …) to your Secret. By
default, webhook targets on private or loopback addresses are blocked. To
allow them, set `notifications.allowPrivateNetworks: true`.

## Private registries

There are two separate pulls:

1. **The Trivy image itself.** By default it is the public
   `ghcr.io/aquasecurity/trivy`. If you mirror it, set `trivy.image` and add a
   pull secret to the scanner ServiceAccount:
   ```yaml
   trivy:
     image: registry.example.com/mirror/trivy:0.67.2
   scanner:
     serviceAccount:
       imagePullSecrets: [{name: mirror-creds}]
   ```
2. **The images Trivy scans.** Trivy pulls these itself from inside the
   scanner pod. Create a `kubernetes.io/dockerconfigjson` Secret in the job
   namespace and reference it:
   ```sh
   kubectl -n krivy-system create secret docker-registry registry-creds \
     --docker-server=registry.example.com --docker-username=… --docker-password=…
   ```
   ```yaml
   scanner:
     registrySecret: registry-creds      # mounted into scanner pods for Trivy
     imagePullSecrets: [registry-creds]  # optional; pod-level pull secrets only help the kubelet pull the Trivy image
   ```

The controller never reads these Secrets. It only references them in the Job
spec.

## Restricting scope

```yaml
kubernetes:
  watchNamespace: production      # Role instead of ClusterRole
  jobNamespace: krivy-scans       # scanner Jobs elsewhere (namespace must exist)
  excludeNamespaces: [kube-system]
```

## NetworkPolicy

```yaml
networkPolicy:
  enabled: true
  ingressFrom:                    # who may call the API on :8080 (default: same namespace)
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: monitoring}
  controller:
    restrictEgress: false         # true: DNS + TCP 443/6443/5432 + extraEgress only
  scanner:
    egressPorts: [443, 80]
    egressCIDRs: [0.0.0.0/0, "::/0"]
    extraEgress: []               # e.g. an in-cluster registry on :5000
```

With `enabled: true`, scanner pods (`app.kubernetes.io/name=krivy`,
`app.kubernetes.io/component=scanner`) accept no ingress. Their egress is
limited to DNS and the configured ports. **Scanner pods need outbound internet
access:** Trivy downloads its vulnerability DB from `ghcr.io` /
`mirror.gcr.io` on every scan and pulls the scanned images from their
registries. If you restrict `egressCIDRs`, include your registries and the DB
mirrors. Air-gapped setups need a registry mirror plus Trivy DB repository
flags in `trivy.extraArgs` (for example `--db-repository`).

When `controller.restrictEgress` is enabled, make sure the Kubernetes API
server, your PostgreSQL host and your webhook targets are reachable on the
listed ports. Some CNIs need an `ipBlock` for the API server endpoint; add it
via `controller.extraEgress`.

## Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: krivy.example.com
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: krivy-tls
      hosts: [krivy.example.com]
```

All API and MCP endpoints require a bearer token, except `/healthz`,
`/readyz`, `/version` and `/api/v1/openapi.yaml`. Still, put the Ingress behind your usual access controls.

## Upgrading and uninstalling

```sh
helm upgrade krivy oci://ghcr.io/l4r-s/charts/krivy -n krivy-system --version <new> -f krivy-values.yaml
helm uninstall krivy -n krivy-system
kubectl -n krivy-system delete pvc krivy-data   # SQLite data, kept by default
```

## Releases and package visibility (maintainers)

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`. That workflow:

* builds a multi-arch image (linux/amd64, linux/arm64) with provenance and
  SBOM, and pushes `ghcr.io/l4r-s/krivy:{X.Y.Z, X.Y, latest}`;
* packages the chart with `version = appVersion = X.Y.Z` and pushes it to
  `oci://ghcr.io/l4r-s/charts/krivy`;
* creates the GitHub release with generated notes and attaches the chart
  `.tgz`.

New GHCR packages are **private** on first push. `GITHUB_TOKEN` cannot change
their visibility, and the REST API has no documented endpoint for it. So after
the first release, set both packages to public once, by hand:

1. https://github.com/users/l4r-s/packages/container/krivy/settings → *Change visibility* → Public
2. https://github.com/users/l4r-s/packages/container/charts%2Fkrivy/settings → *Change visibility* → Public

Check the result with the GitHub CLI (requires a token with `read:packages`):

```sh
gh api /users/l4r-s/packages/container/krivy --jq .visibility
gh api /users/l4r-s/packages/container/charts%2Fkrivy --jq .visibility
```

In the same settings page, under *Manage Actions access*, give the repository
`l4r-s/krivy` **write** access to each package. Otherwise later workflow runs
cannot push to a package that was created manually or by another repository.
