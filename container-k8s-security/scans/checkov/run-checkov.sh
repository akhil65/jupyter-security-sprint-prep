#!/usr/bin/env bash
# ============================================================
# run-checkov.sh — IaC Security Scanner
# ============================================================
# Checkov scans Dockerfiles, Kubernetes YAML, Helm charts, and
# Terraform for security misconfigurations against 1000+ policies.
#
# Install: pip install checkov
# Docs:    https://www.checkov.io/
#
# Run from the repo root:
#   bash container-k8s-security/scans/checkov/run-checkov.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"
MANIFESTS="$SCRIPT_DIR/../../k8s-manifests"

command -v checkov >/dev/null 2>&1 || {
  echo "checkov not found. Install: pip install checkov"
  exit 1
}

echo "═══════════════════════════════════════════════════════════"
echo "  Checkov IaC Scan — Jupyter Security Sprint"
echo "═══════════════════════════════════════════════════════════"

# ── 1. Scan K8s manifests (sprint-authored) ─────────────────
echo ""
echo "[1/4] Scanning k8s-manifests/ (vulnerable deployment)..."
checkov -d "$MANIFESTS" \
  --framework kubernetes \
  -o json \
  --output-file-path "$OUT_DIR" \
  --quiet 2>/dev/null \
  || true   # checkov exits 1 when findings exist — that's expected

# Rename to a descriptive name
mv "$OUT_DIR/results_kubernetes.json" "$OUT_DIR/k8s_manifests.json" 2>/dev/null || true

checkov -d "$MANIFESTS" \
  --framework kubernetes \
  -o cli \
  --quiet 2>/dev/null \
  > "$OUT_DIR/k8s_manifests.txt" || true

echo "  -> $OUT_DIR/k8s_manifests.json"
echo "  -> $OUT_DIR/k8s_manifests.txt"

# ── 2. Scan jupyterhub Dockerfiles ──────────────────────────
echo ""
echo "[2/4] Scanning repos/jupyterhub/ Dockerfiles..."
checkov -d "$ROOT/repos/jupyterhub" \
  --framework dockerfile \
  -o json \
  --output-file-path "$OUT_DIR" \
  --quiet 2>/dev/null || true

mv "$OUT_DIR/results_dockerfile.json" "$OUT_DIR/jupyterhub_dockerfile.json" 2>/dev/null || true

checkov -d "$ROOT/repos/jupyterhub" \
  --framework dockerfile \
  -o cli \
  --quiet 2>/dev/null \
  > "$OUT_DIR/jupyterhub_dockerfile.txt" || true

echo "  -> $OUT_DIR/jupyterhub_dockerfile.json"
echo "  -> $OUT_DIR/jupyterhub_dockerfile.txt"

# ── 3. Scan jupyterlab Dockerfiles (if repo cloned) ─────────
echo ""
if [ -d "$ROOT/repos/jupyterlab" ]; then
  echo "[3/4] Scanning repos/jupyterlab/ Dockerfiles..."
  checkov -d "$ROOT/repos/jupyterlab" \
    --framework dockerfile \
    -o json \
    --output-file-path "$OUT_DIR" \
    --quiet 2>/dev/null || true
  mv "$OUT_DIR/results_dockerfile.json" "$OUT_DIR/jupyterlab_dockerfile.json" 2>/dev/null || true
  echo "  -> $OUT_DIR/jupyterlab_dockerfile.json"
else
  echo "[3/4] repos/jupyterlab/ not found — skipping."
  echo "      Clone first: git clone --depth=1 https://github.com/jupyterlab/jupyterlab.git repos/jupyterlab"
fi

# ── 4. Scan Terraform (training_playground) ─────────────────
echo ""
echo "[4/4] Scanning training_playground Terraform..."
checkov -d "$ROOT/appsec_sprint_evaluator/training_playground" \
  --framework terraform \
  -o json \
  --output-file-path "$OUT_DIR" \
  --quiet 2>/dev/null || true
mv "$OUT_DIR/results_terraform.json" "$OUT_DIR/training_playground_terraform.json" 2>/dev/null || true
echo "  -> $OUT_DIR/training_playground_terraform.json"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Done. Review JSON results or run the evaluator:"
echo "  python3 -c \"\""
echo "  To see a summary:"
echo "    cat $OUT_DIR/k8s_manifests.txt"
echo "═══════════════════════════════════════════════════════════"
