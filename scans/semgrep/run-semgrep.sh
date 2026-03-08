#!/usr/bin/env bash
# run-semgrep.sh
# Run semgrep with OWASP Top 10 and Python security rulesets.
# Requires: semgrep installed (pip install semgrep) and network access to semgrep registry.
# Execute from the repo root: bash scans/semgrep/run-semgrep.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REPOS=("jupyter_server" "jupyterhub")
RULESETS=("p/owasp-top-ten" "p/python" "p/security-audit")

for REPO in "${REPOS[@]}"; do
  echo "=== semgrep: $REPO ==="
  REPO_PATH="$ROOT/repos/$REPO"
  OUT_DIR="$SCRIPT_DIR"

  for RULESET in "${RULESETS[@]}"; do
    RULESET_SLUG="${RULESET//\//-}"  # e.g. p/owasp-top-ten -> p-owasp-top-ten
    echo "  Running ruleset: $RULESET"

    semgrep scan \
      --config "$RULESET" \
      --json \
      --output "$OUT_DIR/${REPO}_${RULESET_SLUG}.json" \
      --no-git-ignore \
      "$REPO_PATH" \
      2>&1 | grep -E "^(Running|Scanning|Found|Findings|Error)" || true

    semgrep scan \
      --config "$RULESET" \
      --text \
      --output "$OUT_DIR/${REPO}_${RULESET_SLUG}.txt" \
      --no-git-ignore \
      "$REPO_PATH" \
      2>&1 | grep -E "^(Running|Scanning|Found|Findings|Error)" || true
  done

  # Combined run for a summary
  echo "  Running combined rulesets..."
  semgrep scan \
    --config "p/owasp-top-ten" \
    --config "p/python" \
    --config "p/security-audit" \
    --json \
    --output "$OUT_DIR/${REPO}_combined.json" \
    --no-git-ignore \
    "$REPO_PATH" \
    2>&1 | grep -E "^(Running|Scanning|Found|Findings|Error)" || true

  echo "  Done: $REPO"
  echo ""
done

echo "All semgrep scans complete. Results saved to scans/semgrep/"
echo "Review combined results: scans/semgrep/<repo>_combined.json"
