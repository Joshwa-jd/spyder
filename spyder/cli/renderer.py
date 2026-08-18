"""Output rendering surface.

Reusable Rich renderables (tables and panels) that commands print. All output
is routed through the single Rich console; these builders keep result rendering
consistent across the CLI, REPL, and reports.
"""
from __future__ import annotations

from ..ui.display import (
    findings_table,
    history_table,
    stats_panel,
    workspaces_table,
)

__all__ = [
    "findings_table",
    "history_table",
    "stats_panel",
    "workspaces_table",
]
