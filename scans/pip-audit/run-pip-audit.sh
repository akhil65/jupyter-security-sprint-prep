#!/usr/bin/env bash
# run-pip-audit.sh
# Run pip-audit against both repos on sprint day (requires network access).
# Execute from the repo root: bash scans/pip-audit/run-pip-audit.sh
#
# Python version note: tomllib is built-in from Python 3.11+.
# On Python 3.8-3.10, install the backport first: pip install tomli
# This script falls back to tomli automatically if tomllib is unavailable.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Helper: extract dependencies from a pyproject.toml using tomllib (3.11+) or
# tomli (3.8+). Exits with a clear error message if neither is available.
extract_deps() {
  local toml_path="$1"
  python3 -c "
import pathlib, sys
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        sys.exit(
            'ERROR: tomllib/tomli not found. '
            'Python 3.11+ has tomllib built-in. '
            'For Python 3.8-3.10 run: pip install tomli'
        )
data = tomllib.loads(pathlib.Path('${toml_path}').read_bytes().decode())
deps = data.get('project', {}).get('dependencies', [])
print('\n'.join(deps))
"
}

echo "=== pip-audit: jupyter_server ==="
pip-audit \
  --requirement <(extract_deps "$ROOT/repos/jupyter_server/pyproject.toml") \
  --format json \
  --no-deps \
  --output "$SCRIPT_DIR/jupyter_server.json"

pip-audit \
  --requirement <(extract_deps "$ROOT/repos/jupyter_server/pyproject.toml") \
  --format columns \
  --no-deps \
  --output "$SCRIPT_DIR/jupyter_server.txt"

echo ""
echo "=== pip-audit: jupyterhub ==="
pip-audit \
  --requirement "$ROOT/repos/jupyterhub/requirements.txt" \
  --format json \
  --no-deps \
  --output "$SCRIPT_DIR/jupyterhub.json"

pip-audit \
  --requirement "$ROOT/repos/jupyterhub/requirements.txt" \
  --format columns \
  --no-deps \
  --output "$SCRIPT_DIR/jupyterhub.txt"

echo ""
echo "Done. Results saved to scans/pip-audit/"
