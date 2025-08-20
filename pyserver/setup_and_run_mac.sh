#!/usr/bin/env bash
set -euo pipefail

# Change to script directory
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 not found. Please install Python 3.10+ and try again." >&2
  exit 1
fi

echo "[1/4] Creating virtual environment (venv)..."
if [ ! -d venv ]; then
  python3 -m venv venv
else
  echo "venv already exists"
fi

echo "[2/4] Upgrading pip..."
./venv/bin/python -m pip install --upgrade pip

echo "[3/4] Installing dependencies..."
./venv/bin/pip install --disable-pip-version-check --no-input flask flask-cors webauthn

echo "[4/4] Starting Flask server on http://localhost:5000 ..."
exec ./venv/bin/python app.py
