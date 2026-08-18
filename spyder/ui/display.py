"""Rich data-table components for the SPYDER console: findings, history,
workspaces, and the one-line run summary.

Rendering philosophy (matches sqlmap / nuclei / ffuf / gobuster):
  * left-aligned, information-dense output — no giant centered boxes
  * one thin rule separates the banner from the session; no blank filler regions
Every line earns its place.

Terminal ownership (banner, clear, restore, prompt-adjacent screen state) lives
solely in ``spyder.ui.terminal`` — this module renders *content*, never chrome.
"""
from __future__ import annotations

from pathlib import Path

from rich.table import Table
from rich.text import Text

from ..core.models import Finding
from . import theme
from .theme import (
    DIM_GREY,
    NEON_RED,
    SEVERITY_STYLES,
    SUCCESS,
)

LOGO_SVG = Path(__file__).parent / "assets" / "spyder_logo.svg"


def findings_table(findings: list[Finding]) -> Table:
    """Findings ranked by severity, with exact duplicates collapsed into a count.

    Ordering: severity (highest first), then endpoint, then title — so the most
    urgent, same-target findings cluster together. Findings that are identical in
    severity/title/endpoint/source are grouped and shown once with an ``×N`` count
    rather than repeated rows.
    """
    table = theme.base_table("SPYDER · Findings", expand=True)
    table.add_column("Sev", width=9, no_wrap=True)
    table.add_column("#", justify="right", width=3, no_wrap=True)
    table.add_column("Title")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("Source", width=24, overflow="fold")

    if not findings:
        table.add_row(Text("—", style=theme.MUTED), "", "no findings yet", "", "")
        return table

    grouped: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.severity.rank, f.title, f.endpoint or "", f.source)
        grouped.setdefault(key, []).append(f)

    ordered = sorted(
        grouped.items(),
        key=lambda kv: (-kv[0][0], kv[0][2], kv[0][1]),
    )
    for (_rank, title, endpoint, source), group in ordered:
        sev = group[0].severity
        count = len(group)
        table.add_row(
            Text(sev.value.upper(), style=SEVERITY_STYLES[sev]),
            str(count) if count > 1 else "",
            title,
            endpoint or "—",
            source,
        )
    return table


def history_table(rows: list[dict], workspace: str) -> Table:
    """Scan/connector history for a workspace as a ranked, structured table.

    The workspace is implicit (history is always scoped to the current one), so it
    is named in the title rather than repeated on every row — leaving the width for
    the Target column, which is the information that actually varies row-to-row.
    """
    table = theme.base_table(f"SPYDER · History · {workspace}", expand=True)
    table.add_column("Timestamp", width=19, no_wrap=True)
    table.add_column("Activity", width=10, no_wrap=True)
    table.add_column("Target", overflow="fold", ratio=1)
    table.add_column("Endpoints", justify="right", width=9, no_wrap=True)
    table.add_column("Findings", justify="right", width=8, no_wrap=True)
    table.add_column("Duration", justify="right", width=8, no_wrap=True)
    table.add_column("Status", width=11, no_wrap=True)

    _status_styles = {
        "complete": SUCCESS,
        "empty": theme.WARNING,
        "unreachable": NEON_RED,
    }
    for r in rows:
        dur = r.get("duration")
        dur_s = f"{dur:.1f}s" if isinstance(dur, int | float) else "—"
        status = r.get("status") or "—"
        style = _status_styles.get(status, theme.DIM_GREY)
        eps = r.get("endpoints")
        fnd = r.get("findings")
        table.add_row(
            (r.get("created") or "")[:19].replace("T", " "),
            str(r.get("kind") or "—"),
            r.get("target") or "—",
            str(eps) if eps is not None else "—",
            str(fnd) if fnd is not None else "—",
            dur_s,
            Text(str(status), style=style),
        )
    return table


def stats_panel(requests: int, endpoints: int, findings: int, elapsed: float) -> Table:
    """Compact one-line run summary (ffuf/sqlmap style) rather than a boxed panel."""
    grid = Table.grid(padding=(0, 3))
    for _ in range(4):
        grid.add_column(no_wrap=True)
    grid.add_row(
        f"[{DIM_GREY}]requests[/] [bold {NEON_RED}]{requests}[/]",
        f"[{DIM_GREY}]endpoints[/] [bold {NEON_RED}]{endpoints}[/]",
        f"[{DIM_GREY}]findings[/] [bold {NEON_RED}]{findings}[/]",
        f"[{DIM_GREY}]elapsed[/] [bold {NEON_RED}]{elapsed:.1f}s[/]",
    )
    return grid


def workspaces_table(rows: list[dict]) -> Table:
    table = theme.base_table("SPYDER · Workspaces")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Created", overflow="fold")
    for r in rows:
        table.add_row(r["name"], r.get("target") or "—", r["created"][:19])
    return table
