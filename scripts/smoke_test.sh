#!/usr/bin/env bash
# Smoke test: verify NIM connectivity and OpenShell gateway before the demo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "ERROR: virtualenv not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

echo "==> Checking OpenShell gateway..."
if command -v openshell >/dev/null 2>&1; then
  openshell status || echo "WARNING: openshell gateway not connected"
else
  echo "WARNING: openshell CLI not found — Tool-Executor step will fail"
fi

echo ""
echo "==> Checking NIM connectivity..."
"$PY" nemoclaw.py

echo ""
echo "Smoke test complete."
