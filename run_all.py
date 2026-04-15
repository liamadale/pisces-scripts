#!/usr/bin/env python3
"""Combined PISCES Web UI — all three apps on one port via DispatcherMiddleware."""

import argparse
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from dotenv import load_dotenv

load_dotenv()

from src.utils.dns import setup_dns

setup_dns()

from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

from apps.hub.app import create_app as create_hub
from apps.opensearch_web.app import create_app as create_opensearch
from apps.mantis_web.app import create_app as create_mantis
from apps.dashboard_web.app import create_app as create_dashboard

application = DispatcherMiddleware(
    create_hub(),
    {
        "/opensearch": create_opensearch(),
        "/mantis": create_mantis(),
        "/dashboard": create_dashboard(),
    },
)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PISCES Combined Web UI")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true", default=False)
    args = parser.parse_args()
    run_simple(
        args.host,
        args.port,
        application,
        use_reloader=False,
        use_debugger=args.debug,
        threaded=True,
    )
