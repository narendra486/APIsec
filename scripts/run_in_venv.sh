#!/usr/bin/env bash
set -euo pipefail
# run_in_venv.sh
# Usage: bash run_in_venv.sh <script-or-module> [args...]
# If a project .venv exists with a python executable, use it. Otherwise fall back to system python3.

# Run from workspace root. Use PWD to detect .venv in workspace.
VENV_PY="${PWD}/.venv/bin/python3"

if [ -x "$VENV_PY" ]; then
  exec "$VENV_PY" "$@"
else
  exec python3 "$@"
fi
