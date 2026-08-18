"""SPYDER command-line interface package.

This is the documented CLI surface. Historically these concerns live under
``spyder.ui`` (shell, banner, display) and ``spyder.__main__`` (argument parsing
and dispatch); ``spyder.cli`` re-exports them under stable, purpose-named modules
so operators and plugin authors have one obvious place to import the CLI from:

    from spyder.cli import main, build_parser, run_console, render_banner
    from spyder.cli.banner import render_banner
    from spyder.cli.progress import info, ok, err, warn

The re-exports are aliases, not copies — there is exactly one implementation of
each behind them, so nothing here can drift from the code it fronts.
"""
from __future__ import annotations

from .banner import banner_renderable, render_banner
from .dispatcher import main
from .parser import build_parser
from .shell import run_console

__all__ = [
    "banner_renderable",
    "build_parser",
    "main",
    "render_banner",
    "run_console",
]
