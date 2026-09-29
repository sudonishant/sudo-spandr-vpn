#!/usr/bin/env bash
# One-command bootstrap: venv -> deps -> models -> sample captures -> dashboard build -> server.
#   ./run.sh                 # start API + dashboard on http://0.0.0.0:8000
#   ./run.sh --port 9000     # different port
#   ./run.sh --no-frontend   # skip the npm build (uses the prebuilt ipsec_xray/webui if present)
#   ./run.sh --test          # run the pytest suite instead of the server
set -euo pipefail
cd "$(dirname "$0")"
PORT=8000; BUILD_FE=1; MODE=serve
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --no-frontend) BUILD_FE=0; shift ;;
    --test) MODE=test; shift ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done

PY=${PYTHON:-python3}
if [ ! -d .venv ]; then
  echo "[1/5] creating virtualenv"; $PY -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q --upgrade pip >/dev/null
python -m pip install -q -r requirements.txt
echo "[1/5] dependencies ok ($(python --version))"

models_ok() {
  [ -f models/traffic_rf.joblib ] && [ -f models/cipher_rf.joblib ] && [ -f models/mode_rf.joblib ] && \
  python - <<'PY'
import json, sys, sklearn
meta = json.load(open("models/meta.json"))
sys.exit(0 if meta.get("sklearn") == sklearn.__version__ else 1)
PY
}
if models_ok; then
  echo "[2/5] models present"
else
  echo "[2/5] training ML models for the installed scikit-learn (~1-3 min)"; python -m ipsec_xray.ml.train
fi

if [ ! -f samples/manifest.json ]; then
  echo "[3/5] generating scenario captures"; python -m ipsec_xray.testbed.generate
else
  echo "[3/5] sample captures present ($(ls samples/*.pcap | wc -l) files)"
fi

if [ "$BUILD_FE" = 1 ] && command -v npm >/dev/null 2>&1; then
  if [ ! -f ipsec_xray/webui/index.html ] || [ frontend/src -nt ipsec_xray/webui/index.html ]; then
    echo "[4/5] building dashboard (npm)"; (cd frontend && npm install --no-audit --no-fund --loglevel=error && npm run build)
  else
    echo "[4/5] dashboard build up to date"
  fi
elif [ -f ipsec_xray/webui/index.html ]; then
  echo "[4/5] using prebuilt dashboard"
else
  echo "[4/5] npm not found and no prebuilt dashboard - API + fallback page only"
fi

if [ "$MODE" = test ]; then
  echo "[5/5] running tests"; exec python -m pytest tests -q
fi
echo "[5/5] starting IPsec X-Ray on http://0.0.0.0:${PORT}  (dashboard: /  API docs: /docs)"
exec python -m uvicorn ipsec_xray.api.app:app --host 0.0.0.0 --port "${PORT}"
