"""CLI banner surface — the single banner owner.

There is exactly one banner implementation, in :mod:`spyder.ui.banner`. Every
render path (startup, ``clear``, dashboard exit, CLI one-shot) goes through
:func:`render_banner`. This module re-exports it so ``spyder.cli.banner`` matches
the documented architecture without introducing a second implementation.
"""
from __future__ import annotations

from ..ui.banner import banner_renderable, render_banner

__all__ = ["banner_renderable", "render_banner"]
