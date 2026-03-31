#!/usr/bin/env bash
# ============================================================
# deploy-jupyter.sh
# Deploys JupyterHub to the kind sandbox cluster in either
# vulnerable (for scan demo) or hardened mode.
#
# Usage:
#   bash sandbox/deploy-jupyter.sh --mode vulnerable
#   bash sandbox/deploy-jupyter.sh --mode hardened
#   bash sandbox/deploy-jupyter.sh --mode vulnerable --with-helm
# ============================================================
set -euo pipefail

MODE=""
USE_HELM=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../k8s-manifests"

for arg in "$@"; do
  case $arg in
    --mode) shift ;;
    vulnerable|hardened) MODE=$arg ;;
    --with-helm) USE_HELM=true ;;
  esac
done

[[ -z "$MODE" ]] && { echo "Usage: $0 --mode vulnerable|hardened"; exit 1; }

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }

echo ""
echo "Deploying JupyterHub in ${MODE} mode..."
echo ""

if [[ "$MODE" == "vulnerable" ]]; then
  echo "Applying vulnerable manifests (for security scanning demo)..."
  kubectl apply -f "$MANIFESTS_DIR/jupyterhub-deployment.yaml"
  kubectl apply -f "$MANIFESTS_DIR/single-user-profile.yaml"
  warn "Deployed with intentional vulnerabilities — DO NOT expose to internet."

elif [[ "$MODE" == "hardened" ]]; then
  echo "Applying hardened manifests..."
  kubectl apply -f "$MANIFESTS_DIR/jupyterhub-deployment-hardened.yaml"
  kubectl apply -f "$MANIFESTS_DIR/network-policy.yaml"
  ok "Deployed with hardened configuration."
fi

# ── Wait for pods ─────────────────────────────────────────────
echo ""
echo "Waiting for hub pod to be ready..."
kubectl wait --namespace jupyter \
  --for=condition=ready pod \
  --selector=app=jupyterhub,component=hub \
  --timeout=120s 2>/dev/null || warn "Hub pod not ready yet — check: kubectl get pods -n jupyter"

# ── Port-forward for local access ────────────────────────────
echo ""
echo "To access JupyterHub locally:"
if [[ "$MODE" == "vulnerable" ]]; then
  echo "  kubectl port-forward svc/jupyterhub 8080:80 -n jupyter"
  echo "  Then open: http://localhost:8080"
else
  echo "  Add to /etc/hosts: 127.0.0.1 jupyter.example.com"
  echo "  Then open: https://jupyter.example.com"
fi

echo ""
ok "Deployment complete. Run scans against this live cluster:"
echo "  bash scans/kubescape/run-kubescape.sh --live-cluster"
echo "  bash scans/checkov/run-checkov.sh"
