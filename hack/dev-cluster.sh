#!/bin/sh
# Local k3d development cluster for Krivy.
#
#   sh hack/dev-cluster.sh <command>
#
# Commands:
#   create           create (or start) the k3d cluster "krivy-dev" and write .dev/kubeconfig
#   seed             apply hack/dev/seed.yaml (namespaces, sample workloads, scanner SA)
#   status           show cluster, node and seeded workload status
#   stop | start     stop / start the cluster containers (state is preserved)
#   destroy          delete the cluster and .dev/kubeconfig (.dev/krivy.db is kept)
#   kubeconfig       print an `export KUBECONFIG=...` line for the dev cluster
#   kubeconfig-path  print the absolute path of the dedicated kubeconfig
#   check-context    fail unless .dev/kubeconfig exists and targets k3d-krivy-dev
#
# The script never reads or modifies ~/.kube/config: every kubectl call passes
# --kubeconfig .dev/kubeconfig --context k3d-krivy-dev explicitly.
#
# POSIX sh; works on macOS (Docker Desktop, Colima, OrbStack) and Linux.

set -eu

CLUSTER=krivy-dev
CONTEXT=k3d-$CLUSTER
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEV_DIR=$ROOT/.dev
KUBECONFIG_FILE=$DEV_DIR/kubeconfig
SEED=$ROOT/hack/dev/seed.yaml
# Optional: pin the k3s image, e.g. KRIVY_DEV_K3S_IMAGE=rancher/k3s:v1.33.4-k3s1
K3S_IMAGE=${KRIVY_DEV_K3S_IMAGE:-}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

os_name() { uname -s 2>/dev/null || echo unknown; }

install_hint() {
  tool=$1
  os=$(os_name)
  printf '\n%s is required but was not found in PATH.\n' "$tool" >&2
  case $tool in
    docker)
      if [ "$os" = Darwin ]; then
        cat >&2 <<'EOF'
Install a Docker runtime for macOS, for example:
  - Docker Desktop: https://docs.docker.com/desktop/setup/install/mac-install/
  - OrbStack:       https://orbstack.dev
  - Colima:         brew install colima docker && colima start --cpu 2 --memory 4
EOF
      else
        cat >&2 <<'EOF'
Install Docker Engine for Linux: https://docs.docker.com/engine/install/
  then add yourself to the docker group: sudo usermod -aG docker "$USER" (re-login)
EOF
      fi
      ;;
    k3d)
      cat >&2 <<'EOF'
Install k3d (https://k3d.io), for example:
  macOS:  brew install k3d
  Linux/macOS (official script, pin a version):
          curl -fsSL https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | TAG=v5.8.3 bash
EOF
      ;;
    kubectl)
      if [ "$os" = Darwin ]; then
        cat >&2 <<'EOF'
Install kubectl: brew install kubectl
  or see https://kubernetes.io/docs/tasks/tools/install-kubectl-macos/
EOF
      else
        cat >&2 <<'EOF'
Install kubectl: https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
EOF
      fi
      ;;
  esac
  printf '\nSee docs/development.md for details.\n' >&2
}

require() {
  missing=0
  for t in "$@"; do
    if ! have "$t"; then
      install_hint "$t"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
}

require_docker_running() {
  if ! docker info >/dev/null 2>&1; then
    printf '\nerror: the Docker daemon is not reachable (docker info failed).\n' >&2
    if [ "$(os_name)" = Darwin ]; then
      cat >&2 <<'EOF'
Start your Docker runtime: open Docker Desktop / OrbStack, or run `colima start`.
If you use Colima or OrbStack, check the active docker context: docker context ls
EOF
    else
      cat >&2 <<'EOF'
Start Docker: sudo systemctl start docker
If you get a permission error, add yourself to the docker group:
  sudo usermod -aG docker "$USER"   (then log out and back in)
EOF
    fi
    exit 1
  fi
}

kc() {
  kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CONTEXT" "$@"
}

cluster_exists() {
  k3d cluster get "$CLUSTER" >/dev/null 2>&1
}

write_kubeconfig() {
  mkdir -p "$DEV_DIR"
  tmp=$KUBECONFIG_FILE.tmp.$$
  # Restrict permissions before the credentials are written.
  ( umask 077 && k3d kubeconfig get "$CLUSTER" >"$tmp" ) || { rm -f "$tmp"; die "k3d kubeconfig get failed"; }
  mv "$tmp" "$KUBECONFIG_FILE"
  ctx=$(kubectl --kubeconfig "$KUBECONFIG_FILE" config current-context 2>/dev/null || true)
  [ "$ctx" = "$CONTEXT" ] || die "unexpected context '$ctx' in $KUBECONFIG_FILE (want $CONTEXT)"
  log "wrote $KUBECONFIG_FILE (context $CONTEXT)"
}

wait_ready() {
  log "waiting for the node to become Ready"
  i=0
  until kc get nodes >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -le 60 ] || die "API server did not become reachable"
    sleep 2
  done
  kc wait --for=condition=Ready node --all --timeout=180s >/dev/null
  # CoreDNS is needed by scanner pods (registry and Trivy DB lookups).
  kc -n kube-system rollout status deployment/coredns --timeout=180s >/dev/null 2>&1 \
    || warn "coredns not ready yet"
}

cmd_create() {
  require docker k3d kubectl
  require_docker_running
  mkdir -p "$DEV_DIR"
  if cluster_exists; then
    log "cluster $CLUSTER already exists; making sure it is running"
    k3d cluster start "$CLUSTER" --wait >/dev/null
  else
    log "creating k3d cluster $CLUSTER"
    if [ -n "$K3S_IMAGE" ]; then
      set -- --image "$K3S_IMAGE"
    else
      set --
    fi
    k3d cluster create "$CLUSTER" "$@" \
      --servers 1 --agents 0 --no-lb \
      --k3s-arg '--disable=traefik@server:0' \
      --k3s-arg '--disable=servicelb@server:0' \
      --k3s-arg '--disable=metrics-server@server:0' \
      --kubeconfig-update-default=false \
      --kubeconfig-switch-context=false \
      --wait
  fi
  write_kubeconfig
  wait_ready
  log "cluster ready. Next: make dev-seed && make dev-run"
  printf '%s\n' "To use kubectl: export KUBECONFIG=$KUBECONFIG_FILE"
}

cmd_check_context() {
  if [ ! -f "$KUBECONFIG_FILE" ]; then
    die "$KUBECONFIG_FILE not found - run 'make dev-cluster' first"
  fi
  require kubectl
  ctx=$(kubectl --kubeconfig "$KUBECONFIG_FILE" config current-context 2>/dev/null || true)
  if [ "$ctx" != "$CONTEXT" ]; then
    die "current-context in $KUBECONFIG_FILE is '$ctx', expected '$CONTEXT' - refusing to continue"
  fi
  server=$(kubectl --kubeconfig "$KUBECONFIG_FILE" config view --minify --context "$CONTEXT" \
    -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null || true)
  case $server in
    https://0.0.0.0:* | https://127.0.0.1:* | https://localhost:* | https://\[::1\]:* | https://host.docker.internal:*) ;;
    *) die "API server '$server' is not a local k3d endpoint - refusing to continue" ;;
  esac
}

cmd_seed() {
  require kubectl
  cmd_check_context
  log "applying $SEED"
  # Namespaces first: bare Pods are rejected until each namespace's default
  # ServiceAccount exists.
  kc apply -f "$SEED" --selector krivy.dev/seed-stage=namespace
  for ns in krivy-system production staging; do
    i=0
    until kc -n "$ns" get serviceaccount default >/dev/null 2>&1; do
      i=$((i + 1))
      [ "$i" -ge 60 ] && die "default ServiceAccount in $ns did not appear"
      sleep 1
    done
  done
  kc apply -f "$SEED"
  log "waiting for seeded workloads"
  kc -n production rollout status deployment/web --timeout=180s
  kc -n staging rollout status deployment/web --timeout=180s
  kc -n staging wait --for=condition=Ready pod/debug --timeout=180s
  # Start one CronJob run now so its pod exists without waiting for the schedule.
  if ! kc -n production get jobs -o name 2>/dev/null | grep -q 'report-seed'; then
    kc -n production create job report-seed --from=cronjob/report >/dev/null
  fi
  log "seed complete"
}

cmd_status() {
  require k3d
  k3d cluster list "$CLUSTER" 2>/dev/null || { echo "cluster $CLUSTER does not exist (run make dev-cluster)"; return 0; }
  if [ ! -f "$KUBECONFIG_FILE" ]; then
    echo "no kubeconfig at $KUBECONFIG_FILE"
    return 0
  fi
  require kubectl
  echo
  echo "kubeconfig: $KUBECONFIG_FILE (context $CONTEXT)"
  if ! kc get nodes -o wide 2>/dev/null; then
    echo "API server not reachable (cluster stopped? try make dev-start)"
    return 0
  fi
  echo
  kc get pods -n production -o wide 2>/dev/null || true
  kc get pods -n staging -o wide 2>/dev/null || true
  echo
  echo "scanner jobs (krivy-system):"
  kc -n krivy-system get jobs,pods 2>/dev/null || true
}

cmd_stop() {
  require docker k3d
  require_docker_running
  cluster_exists || die "cluster $CLUSTER does not exist"
  k3d cluster stop "$CLUSTER"
  log "stopped (state preserved; make dev-start to resume)"
}

cmd_start() {
  require docker k3d kubectl
  require_docker_running
  cluster_exists || die "cluster $CLUSTER does not exist - run make dev-cluster"
  k3d cluster start "$CLUSTER" --wait
  # The API port can change across restarts; refresh the dedicated kubeconfig.
  write_kubeconfig
  wait_ready
}

cmd_destroy() {
  require docker k3d
  require_docker_running
  if cluster_exists; then
    k3d cluster delete "$CLUSTER"
  else
    log "cluster $CLUSTER does not exist"
  fi
  rm -f "$KUBECONFIG_FILE"
  log "removed $KUBECONFIG_FILE (local database in $DEV_DIR kept; delete it manually if wanted)"
}

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

case ${1:-} in
  create) cmd_create ;;
  seed) cmd_seed ;;
  status) cmd_status ;;
  stop) cmd_stop ;;
  start) cmd_start ;;
  destroy) cmd_destroy ;;
  kubeconfig) printf 'export KUBECONFIG=%s\n' "$KUBECONFIG_FILE" ;;
  kubeconfig-path) printf '%s\n' "$KUBECONFIG_FILE" ;;
  check-context) cmd_check_context ;;
  -h | --help | help) usage ;;
  *) usage >&2; exit 2 ;;
esac
