#!/usr/bin/env python3
"""PISCES Web UI server entrypoint."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from src.utils.dns import setup_dns
setup_dns()

from src.web.app import create_app
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True, threaded=True)
