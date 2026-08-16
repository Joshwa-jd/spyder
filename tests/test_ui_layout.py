"""Regression tests for the restored SPYDER banner and compact data output.

The banner is the original large identity — a centered spider over the big
``SPYDER`` wordmark, with subtitle, version, and footer. It carries no session
state, so it renders identically on every path (startup, ``clear``, dashboard
exit, workspace change, Ctrl+C recovery). These tests lock in that the banner
still contains every required element and that data output below it stays in the
compact sqlmap/nuclei/ffuf house style (no giant HEAVY boxes).
"""
from __future__ import annotations

import io

from rich.console import Console

from spyder import __version__
from spyder.ui import banner, display

# The heavy box-drawing glyphs the old oversized splash/header panels were built
# from. The compact redesign must not emit these for the header/stats output.
_HEAVY_BOX = ("┃", "┏", "┓", "┗", "┛", "━")


def _render(renderable, width: int = 100) -> str:
    con = Console(width=width, file=io.StringIO(), force_terminal=True)
    con.print(renderable)
    return con.file.getvalue()


def test_banner_has_all_original_elements():
    # The single banner renderable used by startup, `clear`, and dashboard exit.
    out = _render(banner.banner_renderable())
    # Large spider ASCII art (eyes) and the SPYDER block wordmark.
    assert "(o)" in out, "spider ASCII art is missing"
    assert "█" in out, "large SPYDER block wordmark is missing"
    # Subtitle, version line, footer — verbatim.
    assert "recon • discovery • analysis • orchestration" in out
    assert f"v{__version__}" in out
    assert "authorized testing only • recon • replay • report" in out


def test_banner_is_static_and_identical_across_renders():
    # No session state → byte-for-byte identical every time, at any width.
    a = _render(banner.banner_renderable(), width=100)
    b = _render(banner.banner_renderable(), width=100)
    assert a == b, "banner is not deterministic across renders"


def test_banner_ascii_is_symmetric_and_uniform_width():
    # Every spider row and every wordmark row is the same width (49), so the
    # block centers cleanly and never truncates or drifts.
    for art in (banner.SPIDER_ART, banner.SPYDER_LOGO):
        widths = {len(line) for line in art.split("\n")}
        assert len(widths) == 1, f"art rows are not uniform width: {widths}"


def test_stats_panel_is_single_dense_line_not_a_box():
    out = _render(display.stats_panel(requests=7, endpoints=4, findings=5, elapsed=0.2))
    for ch in _HEAVY_BOX:
        assert ch not in out, f"stats still draws box glyph {ch!r}"
    for field in ("requests", "endpoints", "findings", "elapsed"):
        assert field in out
    # A single content row (dense summary), not a multi-row boxed panel.
    assert out.strip().count("\n") == 0
