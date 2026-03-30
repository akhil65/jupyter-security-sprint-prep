#!/usr/bin/env bash
# run-bandit.sh
# Run bandit against the Jupyter repos and write JSON + text output.
# Requires: bandit installed (pip install bandit).
# Execute from the repo root: bash scans/bandit/run-bandit.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPOS=("jupyter_server" "jupyterhub")

for REPO in "${REPOS[@]}"; do
  echo "=== bandit: $REPO ==="
  REPO_PATH="$ROOT/repos/$REPO"
  OUT_JSON="$SCRIPT_DIR/${REPO}.json"
  OUT_TXT="$SCRIPT_DIR/${REPO}.txt"

  bandit -r "$REPO_PATH" \
    --format json \
    --output "$OUT_JSON" \
    --exit-zero \
    2>/dev/null || true

  bandit -r "$REPO_PATH" \
    --format text \
    --output "$OUT_TXT" \
    --exit-zero \
    2>/dev/null || true

  echo "  -> $OUT_JSON"
  echo "  -> $OUT_TXT"
done

# Optional: scan jupyter/security tools/ directory
SECURITY_REPO="$ROOT/repos/security"
if [ -d "$SECURITY_REPO/tools" ]; then
  echo "=== bandit: security/tools ==="
  bandit -r "$SECURITY_REPO/tools" \
    --format json \
    --output "$SCRIPT_DIR/security_tools.json" \
    --exit-zero \
    2>/dev/null || true
  echo "  -> $SCRIPT_DIR/security_tools.json"
fi

echo ""
echo "Done. Results written to $SCRIPT_DIR/"
echo "To filter to HIGH/MEDIUM only, the appsec-eval pipeline does this automatically."
echo "To re-run the full evaluation: appsec-eval --target-repo jupyter_server"
