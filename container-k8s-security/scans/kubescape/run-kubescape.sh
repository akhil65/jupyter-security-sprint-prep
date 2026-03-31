#!/usr/bin/env bash
# ============================================================
# run-kubescape.sh — Kubernetes Security Posture Scanner
# ============================================================
# Kubescape scans K8s manifests and live clusters against
# the NSA/MITRE ATT&CK framework, CIS benchmarks, and
# custom Rego policies.
#
# Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
# Docs:    https://kubescape.io/
#
# Usage:
#   bash run-kubescape.sh                 # static scan of z2jh Helm chart
#   bash run-kubescape.sh --live-cluster  # scan running cluster via kubeconfig
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR"
LIVE_CLUSTER=false

for arg in "$@"; do
  [[ "$arg" == "--live-cluster" ]] && LIVE_CLUSTER=true
done

command -v kubescape >/dev/null 2>&1 || {
  echo "kubescape not found."
  echo "Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash"
  exit 1
}

echo "═══════════════════════════════════════════════════════════"
echo "  Kubescape K8s Security Scan — Jupyter K8s Security"
echo "═══════════════════════════════════════════════════════════"

# ── Resolve scan target ──────────────────────────────────────
# Primary target: rendered z2jh Helm chart (official JupyterHub K8s deployment)
# Fallback: demo manifests in k8s-manifests/
Z2JH_YAML="/tmp/z2jh-rendered.yaml"

if [ -f "$Z2JH_YAML" ]; then
  SCAN_TARGET="$Z2JH_YAML"
  echo "  Target: z2jh rendered Helm chart ($Z2JH_YAML)"
  echo "  (Run run-checkov.sh first to generate this file, or:"
  echo "   helm template jupyterhub jupyterhub/jupyterhub --namespace jupyter > $Z2JH_YAML)"
else
  SCAN_TARGET="$SCRIPT_DIR/../../k8s-manifests"
  echo "  Target: demo k8s-manifests/ (z2jh YAML not found at $Z2JH_YAML)"
  echo "  To scan the real z2jh chart:"
  echo "    helm repo add jupyterhub https://hub.jupyter.org/helm-chart/"
  echo "    helm template jupyterhub jupyterhub/jupyterhub --namespace jupyter > $Z2JH_YAML"
  echo "    then re-run this script"
fi
echo ""

# ── 1. NSA Kubernetes Hardening Framework ───────────────────
echo "[1/3] NSA Kubernetes Hardening Framework..."
kubescape scan framework nsa \
  "$SCAN_TARGET" \
  --format pretty-printer \
  2>/dev/null > "$OUT_DIR/nsa_results.txt" || true

kubescape scan framework nsa \
  "$SCAN_TARGET" \
  --format json \
  2>/dev/null > "$OUT_DIR/nsa_results.json" || true

echo "  -> $OUT_DIR/nsa_results.txt"

# ── 2. MITRE ATT&CK for Containers ──────────────────────────
echo ""
echo "[2/3] MITRE ATT&CK for Containers..."
kubescape scan framework mitre \
  "$SCAN_TARGET" \
  --format pretty-printer \
  2>/dev/null > "$OUT_DIR/mitre_results.txt" || true

kubescape scan framework mitre \
  "$SCAN_TARGET" \
  --format json \
  2>/dev/null > "$OUT_DIR/mitre_results.json" || true

echo "  -> $OUT_DIR/mitre_results.txt"

# ── 3. Live cluster scan (optional) ─────────────────────────
if $LIVE_CLUSTER; then
  echo ""
  echo "[3/3] Live cluster scan via kubeconfig..."
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found"; exit 1; }

  # Scan the jupyter namespace specifically
  kubescape scan framework nsa \
    --namespace jupyter \
    --format pretty-printer \
    2>/dev/null | tee "$OUT_DIR/live_nsa_jupyter_ns.txt" || true

  kubescape scan framework mitre \
    --namespace jupyter \
    --format pretty-printer \
    2>/dev/null > "$OUT_DIR/live_mitre_jupyter_ns.txt" || true

  echo "  -> $OUT_DIR/live_nsa_jupyter_ns.txt"
  echo "  -> $OUT_DIR/live_mitre_jupyter_ns.txt"
else
  echo ""
  echo "[3/3] Live cluster scan skipped."
  echo "      To scan a running cluster: re-run with --live-cluster"
  echo "      (requires kubectl configured with a cluster — kind or real)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Done."
echo "    NSA results  : $OUT_DIR/nsa_results.txt"
echo "    MITRE results: $OUT_DIR/mitre_results.txt"
echo "═══════════════════════════════════════════════════════════"
