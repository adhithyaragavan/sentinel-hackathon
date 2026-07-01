#!/usr/bin/env bash
# Run the full Sentinel pipeline end-to-end for the live demo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "ERROR: virtualenv not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

exec "$PY" pipeline.py
