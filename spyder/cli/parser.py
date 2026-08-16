"""Argument-parser surface.

``build_parser`` constructs the single ``argparse`` parser shared by every
invocation style (``spyder``, ``python -m spyder``, ``python main.py``).
"""
from __future__ import annotations

from ..__main__ import build_parser

__all__ = ["build_parser"]
