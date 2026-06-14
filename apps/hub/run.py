#!/usr/bin/env python3
"""Standalone entry point for the PISCES Hub portal."""

import argparse
import os
import sys

_here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _here not in sys.path:
    sys.path.insert(0, _here)

from dotenv import load_dotenv

load_dotenv()

from apps.hub.app import create_app


def main() -> None:
    """Entry point for `pisces-hub` console script."""
    parser = argparse.ArgumentParser(description="PISCES Hub Portal")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true", default=False)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
