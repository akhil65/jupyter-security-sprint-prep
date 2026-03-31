#!/usr/bin/env bash
# ============================================================
# run-checkov.sh — IaC Security Scanner
# ============================================================
# Checkov scans Dockerfiles, Kubernetes YAML, and Helm charts
# for security misconfigurations against 1000+ policies.
#
# Install: pip install checkov
#          helm repo add jupyterhub https://hub.jupyter.org/helm-chart/
#          helm repo update
# Docs:    https://www.checkov.io/
#
# Run from the repo root:
#   bash container-k8s-security/scans/checkov/run-checkov.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"

command -v checkov >/dev/null 2>&1 || {
  echo "checkov not found. Install: pip install checkov"
  exit 1
}

echo "═══════════════════════════════════════════════════════════"
echo "  Checkov IaC Scan — Jupyter K8s Security"
echo "═══════════════════════════════════════════════════════════"

# ── 1. Render the official z2jh Helm chart → static YAML ────
# This is the REAL K8s deployment config for JupyterHub.
# jupyterhub/jupyterhub repo has no K8s manifests — z2jh does.
echo ""
echo "[1/3] Rendering z2jh Helm chart (official JupyterHub K8s deployment)..."

if ! command -v helm &>/dev/null; then
  echo "  [SKIP] helm not found — install: https://helm.sh/docs/intro/install/"
  echo "         Then: helm repo add jupyterhub https://hub.jupyter.org/helm-chart/"
else
  helm repo add jupyterhub https://hub.jupyter.org/helm-chart/ 2>/dev/null || true
  helm repo update jupyterhub 2>/dev/null || true

  Z2JH_YAML="/tmp/z2jh-rendered.yaml"
  helm template jupyterhub jupyterhub/jupyterhub \
    --namespace jupyter \
    --version 3.3.7 \
    > "$Z2JH_YAML" 2>/dev/null

  echo "  Rendered $(wc -l < "$Z2JH_YAML") lines of K8s YAML"

  checkov -f "$Z2JH_YAML" \
    --framework kubernetes \
    -o cli --quiet 2>/dev/null \
    > "$OUT_DIR/z2jh_k8s_scan.txt" || true

  checkov -f "$Z2JH_YAML" \
    --framework kubernetes \
    -o json --quiet 2>/dev/null \
    > "$OUT_DIR/z2jh_k8s_scan.json" || true

  echo "  -> $OUT_DIR/z2jh_k8s_scan.txt"
  echo "  -> $OUT_DIR/z2jh_k8s_scan.json"
fi

# ── 2. Scan JupyterHub repo Dockerfiles ─────────────────────
echo ""
echo "[2/3] Scanning repos/jupyterhub/ Dockerfiles..."

if [ ! -d "$ROOT/repos/jupyterhub" ]; then
  echo "  [SKIP] repos/jupyterhub not found."
  echo "         Clone: git clone --depth=1 https://github.com/jupyterhub/jupyterhub repos/jupyterhub"
else
  checkov -d "$ROOT/repos/jupyterhub" \
    --framework dockerfile \
    -o cli --quiet 2>/dev/null \
    > "$OUT_DIR/jupyterhub_dockerfile.txt" || true

  checkov -d "$ROOT/repos/jupyterhub" \
    --framework dockerfile \
    -o json --quiet 2>/dev/null \
    > "$OUT_DIR/jupyterhub_dockerfile.json" || true

  echo "  -> $OUT_DIR/jupyterhub_dockerfile.txt"
  echo "  -> $OUT_DIR/jupyterhub_dockerfile.json"
fi

# ── 3. Scan JupyterLab repo Dockerfiles (if cloned) ─────────
echo ""
if [ -d "$ROOT/repos/jupyterlab" ]; then
  echo "[3/3] Scanning repos/jupyterlab/ Dockerfiles..."
  checkov -d "$ROOT/repos/jupyterlab" \
    --framework dockerfile \
    -o cli --quiet 2>/dev/null \
    > "$OUT_DIR/jupyterlab_dockerfile.txt" || true
  echo "  -> $OUT_DIR/jupyterlab_dockerfile.txt"
else
  echo "[3/3] repos/jupyterlab/ not found — skipping."
  echo "      Clone: git clone --depth=1 https://github.com/jupyterlab/jupyterlab repos/jupyterlab"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Done. Key output:"
echo "    z2jh K8s scan : $OUT_DIR/z2jh_k8s_scan.txt"
echo "    Dockerfiles   : $OUT_DIR/jupyterhub_dockerfile.txt"
echo "═══════════════════════════════════════════════════════════"
