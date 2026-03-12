#!/usr/bin/env python3
"""Entrypoint: python src/mantis/threat_model_web_app/run.py"""

import os
import sys

# Ensure repo root is on the path so `from src.mantis.threat_model_web_app...` works
_repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if _repo not in sys.path:
    sys.path.insert(0, _repo)

from src.mantis.threat_model_web_app.app import create_app
from src.mantis.threat_model_web_app.data import FP_ROWS, MALICIOUS_ROWS, TICKETS_BY_ID

app = create_app()

if __name__ == "__main__":
    print(
        f"Loaded: {len(TICKETS_BY_ID):,} tickets  |  "
        f"{len(MALICIOUS_ROWS):,} malicious IPs  |  "
        f"{len(FP_ROWS):,} FP IPs"
    )
    print("Threat Modeling → http://0.0.0.0:5003/")
    app.run(host="0.0.0.0", port=5003, debug=False, threaded=True)
