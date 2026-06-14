#!/usr/bin/env python3
"""PISCES Web UI server entrypoint."""

import argparse
import os
import sys

_repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _repo not in sys.path:
    sys.path.insert(0, _repo)

from dotenv import load_dotenv

load_dotenv()

from src.utils.dns import setup_dns

setup_dns()

from apps.opensearch_web.app import create_app

app = create_app()


def main() -> None:
    """Entry point for `pisces-opensearch` console script."""
    parser = argparse.ArgumentParser(description="PISCES Web UI")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001, help="Port (default: 5001)")
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable Flask debug mode"
    )
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
