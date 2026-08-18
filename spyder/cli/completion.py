"""Tab-completion surface.

``build_completer`` builds the prompt_toolkit ``NestedCompleter`` from the live
command registry (commands + aliases), driving REPL tab-completion.
"""
from __future__ import annotations

from ..ui.shell import _completer as build_completer

__all__ = ["build_completer"]
