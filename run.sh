#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PORT=8050
echo "=================================================="
echo "   SUDO SPANDR — VPN Sentinel & Command Center   "
echo "=================================================="

# Check if port 8050 is in use
if lsof -i :${PORT} >/dev/null 2>&1; then
  echo "Port ${PORT} is currently in use. Killing old instance..."
  fuser -k ${PORT}/tcp || true
  sleep 1
fi

echo "[*] Launching Sudo Spandr on http://0.0.0.0:${PORT} ..."
exec python3 -m uvicorn backend.main:app --host 0.0.0.0 --port "${PORT}"
