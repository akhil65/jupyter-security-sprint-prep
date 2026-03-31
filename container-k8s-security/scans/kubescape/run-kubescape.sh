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
# Run from the repo root:
#   bash container-k8s-security/scans/kubescape/run-kubescape.sh
#   bash container-k8s-security/scans/kubescape/run-kubescape.sh --live-cluster
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="$SCRIPT_DIR/../../k8s-manifests"
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
echo "  Kubescape K8s Security Scan — Jupyter Security Sprint"
echo "═══════════════════════════════════════════════════════════"

# ── 1. Static scan — NSA hardening framework ────────────────
echo ""
echo "[1/4] NSA Kubernetes Hardening Framework (static manifests)..."
kubescape scan framework nsa \
  "$MANIFESTS" \
  --format json \
  --output "$OUT_DIR/nsa_results.json" \
  --verbose 2>/dev/null || true

kubescape scan framework nsa \
  "$MANIFESTS" \
  --format pretty-printer \
  --output "$OUT_DIR/nsa_results.txt" 2>/dev/null || true

echo "  -> $OUT_DIR/nsa_results.json"
echo "  -> $OUT_DIR/nsa_results.txt"

# ── 2. Static scan — MITRE ATT&CK framework ─────────────────
echo ""
echo "[2/4] MITRE ATT&CK for Containers (static manifests)..."
kubescape scan framework mitre \
  "$MANIFESTS" \
  --format json \
  --output "$OUT_DIR/mitre_results.json" \
  --verbose 2>/dev/null || true

kubescape scan framework mitre \
  "$MANIFESTS" \
  --format pretty-printer \
  --output "$OUT_DIR/mitre_results.txt" 2>/dev/null || true

echo "  -> $OUT_DIR/mitre_results.json"

# ── 3. Specific high-value controls ─────────────────────────
echo ""
echo "[3/4] Targeted control scans (privilege escalation + secrets)..."

# C-0016: Allow privilege escalation
kubescape scan control C-0016 "$MANIFESTS" \
  --format json --output "$OUT_DIR/ctrl_C-0016_privilege_escalation.json" 2>/dev/null || true

# C-0012: Applications credentials in configuration files
kubescape scan control C-0012 "$MANIFESTS" \
  --format json --output "$OUT_DIR/ctrl_C-0012_credentials.json" 2>/dev/null || true

# C-0004: Resources
kubescape scan control C-0004 "$MANIFESTS" \
  --format json --output "$OUT_DIR/ctrl_C-0004_resources.json" 2>/dev/null || true

# C-0046: Insecure capabilities
kubescape scan control C-0046 "$MANIFESTS" \
  --format json --output "$OUT_DIR/ctrl_C-0046_capabilities.json" 2>/dev/null || true

echo "  -> $OUT_DIR/ctrl_*.json"

# ── 4. Live cluster scan (optional) ─────────────────────────
if $LIVE_CLUSTER; then
  echo ""
  echo "[4/4] Live cluster scan — scanning all namespaces..."
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found — can't do live cluster scan"; exit 1; }

  # Full posture scan against live cluster
  kubescape scan \
    --format json \
    --output "$OUT_DIR/live_cluster_full.json" \
    --verbose 2>/dev/null || true

  # Summary for the jupyter namespace specifically
  kubescape scan namespace jupyter \
    --format json \
    --output "$OUT_DIR/live_cluster_jupyter_ns.json" 2>/dev/null || true

  echo "  -> $OUT_DIR/live_cluster_full.json"
  echo "  -> $OUT_DIR/live_cluster_jupyter_ns.json"
  echo ""
  echo "  Risk score:"
  kubescape scan namespace jupyter --format pretty-printer 2>/dev/null | grep -E "RISK|Score|Failed|Passed" | head -10 || true
else
  echo ""
  echo "[4/4] Live cluster scan skipped. Re-run with --live-cluster after setup-sandbox.sh."
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Done. Key files:"
echo "    NSA results:   $OUT_DIR/nsa_results.txt"
echo "    MITRE results: $OUT_DIR/mitre_results.txt"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  To view risk score summary:"
echo "    kubescape scan framework nsa $MANIFESTS"
