"""The one and only SPYDER banner — single source of truth.

Every screen that shows the SPYDER identity (startup splash, the ``clear``
command, dashboard exit, workspace/profile changes, Ctrl+C recovery, CLI
scan/crawl headers) renders through :func:`render_banner` and *nothing else*.
There is deliberately no second banner anywhere in the codebase, and this one
takes no session state, so every render path is byte-for-byte identical by
construction — you cannot make one screen's banner differ from another's.

The banner is the original large SPYDER identity:

    * a large, centered spider drawn in ASCII,
    * the large ``SPYDER`` block wordmark beneath it,
    * the subtitle ``recon • discovery • analysis • orchestration``,
    * the version line, and
    * the footer ``authorized testing only • recon • replay • report``.

Screen ownership (clearing / restoring the terminal) stays with
``spyder.ui.terminal`` — the sole owner of raw escape sequences. This module
owns only *what the banner looks like*; it asks ``terminal`` to give it a fresh
screen. That split keeps one owner for ANSI control and one owner for the
banner, with no overlap.
"""
from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group
from rich.rule import Rule
from rich.text import Text

from .. import __version__
from . import terminal
from .theme import DEEP_RED, DIM_GREY, MUTED, NEON_RED

__all__ = ["render_banner", "banner_renderable", "SPIDER_ART", "SPYDER_LOGO"]

# ── ASCII art ──────────────────────────────────────────────────────────────────
#
# Both blocks are exactly 49 columns wide and use only single-width characters,
# so ``Align.center`` centres each as a solid unit at any terminal width and the
# spider's vertical axis lines up under the middle of the wordmark. The spider is
# left-right symmetric by construction (each row mirrors around its centre).

SPIDER_ART = (
    "\\                       |                       /\n"
    " \\        \\             |             /        / \n"
    "  \\        \\      __    |    __      /        /  \n"
    "    \\        \\   _/  \\  |  /  \\_   /        /    \n"
    "     \\        \\ / (o)  \\|/  (o) \\ /        /     \n"
    "      \\________\\   ^    |    ^   /________/      \n"
    "     /        /  \\ __  /|\\  __ /  \\        \\     \n"
    "    /        /    \\/  \\ | /  \\/    \\        \\    \n"
    "   /        /      \\   \\|/   /      \\        \\   \n"
    "  /        /        \\   |   /        \\        \\  \n"
    " /                   \\  |  /                   \\ "
)

SPYDER_LOGO = (
    "███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ \n"
    "██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗\n"
    "███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝\n"
    "╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗\n"
    "███████║██║        ██║   ██████╔╝███████╗██║  ██║\n"
    "╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝"
)

SUBTITLE = "recon • discovery • analysis • orchestration"
FOOTER = "authorized testing only • recon • replay • report"


def banner_renderable() -> Group:
    """The Rich renderable for the SPYDER banner (no terminal side-effects).

    Kept separate from :func:`render_banner` so it can be rendered into a string
    for tests without touching the real screen. Takes no arguments — the banner
    carries no per-session state, which is exactly why every render is identical.
    """
    spider = Align.center(Text(SPIDER_ART, style=DEEP_RED, no_wrap=True))
    logo = Align.center(Text(SPYDER_LOGO, style=f"bold {NEON_RED}", no_wrap=True))
    subtitle = Text(SUBTITLE, style=DIM_GREY, justify="center")
    version = Text(f"v{__version__}", style=MUTED, justify="center")
    footer = Text(FOOTER, style=MUTED, justify="center")
    return Group(
        Text(""),
        spider,
        Text(""),
        logo,
        Text(""),
        subtitle,
        version,
        Rule(style=DEEP_RED),
        footer,
        Text(""),
    )


def render_banner(console: Console, *, clear_first: bool = True) -> None:
    """Paint the SPYDER banner on a fresh screen at row 1, column 1.

    The single entry point for the startup splash, the ``clear`` command,
    dashboard exit, workspace/profile changes, and Ctrl+C recovery — so all of
    them are pixel-identical. Clearing goes through the one terminal owner
    (``spyder.ui.terminal.clear``); ``clear_first=False`` paints in place (used
    by the ``--no-anim`` CLI path and by tests that keep prior output on screen).
    """
    if clear_first:
        terminal.clear()
    console.print(banner_renderable())
