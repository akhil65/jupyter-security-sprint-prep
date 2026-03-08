#!/usr/bin/env bash
# run-pip-audit.sh
# Run pip-audit against both repos on sprint day (requires network access).
# Execute from the repo root: bash scans/pip-audit/run-pip-audit.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== pip-audit: jupyter_server ==="
pip-audit \
  --requirement <(python3 -c "
import tomllib, pathlib
data = tomllib.loads(pathlib.Path('$ROOT/repos/jupyter_server/pyproject.toml').read_bytes().decode())
deps = data.get('project', {}).get('dependencies', [])
print('\n'.join(deps))
") \
  --format json \
  --no-deps \
  --output "$SCRIPT_DIR/jupyter_server.json"

pip-audit \
  --requirement <(python3 -c "
import tomllib, pathlib
data = tomllib.loads(pathlib.Path('$ROOT/repos/jupyter_server/pyproject.toml').read_bytes().decode())
deps = data.get('project', {}).get('dependencies', [])
print('\n'.join(deps))
") \
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
