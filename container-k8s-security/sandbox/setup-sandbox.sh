#!/usr/bin/env bash
# ============================================================
# setup-sandbox.sh
# Provisions the full Jupyter Security Sprint k8s sandbox.
# Run this from the container-k8s-security/ directory.
#
# What it does:
#   1. Checks prerequisites (docker, kind, kubectl, helm)
#   2. Creates a kind cluster with the sprint config
#   3. Installs NGINX Ingress controller
#   4. Optionally installs Calico CNI (NetworkPolicy enforcement)
#   5. Prints next steps
#
# Usage:
#   cd container-k8s-security/
#   bash sandbox/setup-sandbox.sh [--with-calico]
# ============================================================
set -euo pipefail

CLUSTER_NAME="jupyter-security"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_CALICO=false

for arg in "$@"; do
  [[ "$arg" == "--with-calico" ]] && WITH_CALICO=true
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Jupyter Security Sprint — Container/K8s Sandbox Setup"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Prerequisites ─────────────────────────────────────────
echo "Checking prerequisites..."
command -v docker  >/dev/null 2>&1 || fail "docker not found. Install from https://docs.docker.com/get-docker/"
command -v kind    >/dev/null 2>&1 || fail "kind not found. Install: go install sigs.k8s.io/kind@latest  OR  brew install kind"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. Install from https://kubernetes.io/docs/tasks/tools/"
command -v helm    >/dev/null 2>&1 || fail "helm not found. Install from https://helm.sh/docs/intro/install/"

DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
KIND_VER=$(kind version 2>/dev/null | awk '{print $2}')
KUBECTL_VER=$(kubectl version --client -o json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['clientVersion']['gitVersion'])" 2>/dev/null || echo "unknown")
HELM_VER=$(helm version --short 2>/dev/null)

ok "docker $DOCKER_VER"
ok "kind $KIND_VER"
ok "kubectl $KUBECTL_VER"
ok "helm $HELM_VER"

# ── 2. Create kind cluster ────────────────────────────────────
echo ""
echo "Creating kind cluster '$CLUSTER_NAME'..."

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  warn "Cluster '$CLUSTER_NAME' already exists. Skipping creation."
  warn "To recreate: kind delete cluster --name $CLUSTER_NAME && bash $0"
else
  KIND_CONFIG="$SCRIPT_DIR/kind-config.yaml"
  if $WITH_CALICO; then
    # For Calico we must disable the default CNI
    echo "  (Calico mode: disabling kind default CNI)"
    sed 's/disableDefaultCNI: false/disableDefaultCNI: true/' "$KIND_CONFIG" > /tmp/kind-calico-config.yaml
    KIND_CONFIG="/tmp/kind-calico-config.yaml"
  fi

  kind create cluster --config "$KIND_CONFIG"
  ok "Cluster created."
fi

# ── 3. Set kubectl context ────────────────────────────────────
kubectl config use-context "kind-${CLUSTER_NAME}"
ok "kubectl context set to kind-${CLUSTER_NAME}"

# ── 4. Install Calico (optional, for NetworkPolicy enforcement) ──
if $WITH_CALICO; then
  echo ""
  echo "Installing Calico CNI (NetworkPolicy enforcement)..."
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
  echo "Waiting for Calico pods..."
  kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=120s
  ok "Calico ready."
else
  warn "Using kind's default CNI (kindnet). NetworkPolicy is NOT enforced."
  warn "Re-run with --with-calico to enable NetworkPolicy enforcement."
fi

# ── 5. Install NGINX Ingress controller ──────────────────────
echo ""
echo "Installing NGINX Ingress controller..."
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.0/deploy/static/provider/kind/deploy.yaml
echo "Waiting for ingress-nginx to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=120s
ok "NGINX Ingress ready."

# ── 6. Create jupyter namespace ──────────────────────────────
echo ""
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: jupyter
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
EOF
ok "Namespace 'jupyter' created."

# ── 7. Summary ───────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Sandbox ready! Next steps:"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Deploy Jupyter (vulnerable for scanning):"
echo "    bash sandbox/deploy-jupyter.sh --mode vulnerable"
echo ""
echo "  Deploy Jupyter (hardened, for comparison):"
echo "    bash sandbox/deploy-jupyter.sh --mode hardened"
echo ""
echo "  Run security scans:"
echo "    bash scans/checkov/run-checkov.sh"
echo "    bash scans/kubescape/run-kubescape.sh --live-cluster"
echo "    bash scans/grype/run-grype.sh"
echo ""
echo "  Tear down:"
echo "    kind delete cluster --name $CLUSTER_NAME"
echo ""
