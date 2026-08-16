"""Command dispatch surface.

``main`` is the single entry point: it parses arguments and dispatches either to
the interactive REPL (no subcommand) or to the matching one-shot command handler.
"""
from __future__ import annotations

from ..__main__ import main

__all__ = ["main"]
