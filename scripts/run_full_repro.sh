#!/usr/bin/env bash
set -euo pipefail
# Wrapper to run a full offline reproduction:
#  - start mock server in background
#  - run reproduce_findings.py against the mock
#  - generate the report
#  - stop mock server

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOCK_HOST="127.0.0.1:8000"

echo "Starting mock server..."
bash "$ROOT/scripts/run_in_venv.sh" "$ROOT/scripts/mock_server.py" &
MOCK_PID=$!
echo $MOCK_PID > /tmp/mock_server.pid
sleep 0.3

echo "Running reproduction against mock ($MOCK_HOST)..."
MOCK_HOST=${MOCK_HOST} bash "$ROOT/scripts/run_in_venv.sh" "$ROOT/scripts/reproduce_findings.py"

echo "Generating combined report..."
bash "$ROOT/scripts/run_in_venv.sh" "$ROOT/scripts/generate_repro_report.py"

echo "Stopping mock server (pid=$MOCK_PID)..."
kill "$MOCK_PID" 2>/dev/null || true
sleep 0.2
rm -f /tmp/mock_server.pid || true

echo "Done. Reports are in $ROOT/artifacts/repro/"
