#!/usr/bin/env bash
# ============================================================
# run-grype.sh — Container Image CVE Scanner
# ============================================================
# Grype scans container images and filesystems for known CVEs
# using data from NVD, GitHub Advisories, and OS package DBs.
#
# Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# Docs:    https://github.com/anchore/grype
#
# Requires Docker to pull images.
# Run from the repo root:
#   bash container-k8s-security/scans/grype/run-grype.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR"

# Images to scan — official Jupyter images
JUPYTERHUB_IMAGE="quay.io/jupyterhub/jupyterhub:5.3.0"
JUPYTERLAB_IMAGE="quay.io/jupyter/scipy-notebook:2024-10-07"
POSTGRES_IMAGE="postgres:9.3"   # Used in jupyterhub postgres example — very outdated

command -v grype >/dev/null 2>&1 || {
  echo "grype not found."
  echo "Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
  exit 1
}

command -v docker >/dev/null 2>&1 || {
  echo "docker not found — required to pull images before scanning."
  exit 1
}

echo "═══════════════════════════════════════════════════════════"
echo "  Grype Container Image CVE Scan — Jupyter Security Sprint"
echo "═══════════════════════════════════════════════════════════"

# Update grype DB before scanning
echo ""
echo "Updating grype vulnerability database..."
grype db update

# ── 1. JupyterHub image ─────────────────────────────────────
echo ""
echo "[1/3] Scanning JupyterHub image: $JUPYTERHUB_IMAGE"
grype "$JUPYTERHUB_IMAGE" \
  --output json \
  --file "$OUT_DIR/jupyterhub_image.json" \
  --only-fixed false \
  --fail-on critical 2>/dev/null || true

# Human-readable summary (HIGH + CRITICAL only)
grype "$JUPYTERHUB_IMAGE" \
  --output table \
  --only-fixed false 2>/dev/null \
  | grep -E "^(NAME|.*Critical|.*High)" \
  > "$OUT_DIR/jupyterhub_image_summary.txt" || true

echo "  -> $OUT_DIR/jupyterhub_image.json"
echo "  -> $OUT_DIR/jupyterhub_image_summary.txt"

# ── 2. JupyterLab / scipy-notebook image ────────────────────
echo ""
echo "[2/3] Scanning JupyterLab image: $JUPYTERLAB_IMAGE"
grype "$JUPYTERLAB_IMAGE" \
  --output json \
  --file "$OUT_DIR/jupyterlab_image.json" \
  --only-fixed false \
  --fail-on critical 2>/dev/null || true

grype "$JUPYTERLAB_IMAGE" \
  --output table \
  --only-fixed false 2>/dev/null \
  | grep -E "^(NAME|.*Critical|.*High)" \
  > "$OUT_DIR/jupyterlab_image_summary.txt" || true

echo "  -> $OUT_DIR/jupyterlab_image.json"
echo "  -> $OUT_DIR/jupyterlab_image_summary.txt"

# ── 3. postgres:9.3 — known very old image in jupyterhub example ──
echo ""
echo "[3/3] Scanning deprecated postgres:9.3 (used in jupyterhub examples/postgres/)..."
grype "$POSTGRES_IMAGE" \
  --output json \
  --file "$OUT_DIR/postgres93_image.json" \
  --only-fixed false \
  --fail-on high 2>/dev/null || true

grype "$POSTGRES_IMAGE" \
  --output table \
  --only-fixed false 2>/dev/null \
  | grep -E "^(NAME|.*Critical|.*High)" \
  > "$OUT_DIR/postgres93_summary.txt" || true

echo "  -> $OUT_DIR/postgres93_image.json"
echo "  -> $OUT_DIR/postgres93_summary.txt"

# ── Summary ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Scan complete. Critical/High summary:"
echo "═══════════════════════════════════════════════════════════"
for f in "$OUT_DIR"/*_summary.txt; do
  echo ""
  echo "  $(basename $f):"
  cat "$f" | head -20
done

echo ""
echo "Full JSON results in: $OUT_DIR/"
echo "To count CVEs by severity:"
echo "  python3 -c \""
echo "  import json,sys"
echo "  from collections import Counter"
echo "  d = json.load(open('$OUT_DIR/jupyterhub_image.json'))"
echo "  c = Counter(m['vulnerability']['severity'] for m in d.get('matches',[]))"
echo "  print(dict(c))\""
