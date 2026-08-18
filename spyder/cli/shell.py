"""Interactive REPL surface.

Re-exports the prompt_toolkit-driven console from :mod:`spyder.ui.shell`.
``run_console`` is the interactive REPL entered when ``spyder`` runs with no
subcommand.
"""
from __future__ import annotations

from ..ui.shell import ShellContext, run_console

__all__ = ["ShellContext", "run_console"]
