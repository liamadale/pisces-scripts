#!/usr/bin/env python3
"""Thin shim → apps/mantis_web/run.py"""
import os
import runpy
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

runpy.run_path(
    os.path.join(_here, "apps", "mantis_web", "run.py"),
    run_name="__main__",
)
