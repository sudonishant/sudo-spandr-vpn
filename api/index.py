import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Set writable data directory for serverless environment (e.g. /tmp)
os.environ.setdefault("IPSEC_XRAY_DATA", "/tmp/ipsec_xray_data")
os.environ.setdefault("IPSEC_XRAY_SAMPLES", os.path.join(BASE_DIR, "samples"))
os.environ.setdefault("IPSEC_XRAY_MODELS", os.path.join(BASE_DIR, "models"))

from ipsec_xray.api.app import app

# Add standard health check endpoint for monitoring/uptime check
@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "service": "sudo-spandr-c4i"}
