"""Centralized cyberpunk theme — single source of truth for all SPYDER UI styling.

Black background · aggressive neon-red palette · cinematic HUD chrome.
Import constants and helpers from here instead of hardcoding colors anywhere.
"""
from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from ..core.models import Severity

# ---------------------------------------------------------------------------
# Palette — hex constants
# ---------------------------------------------------------------------------

NEON_RED  = "#ff2b3d"   # primary brand red: prompt, borders, highlights
DEEP_RED  = "#cc1020"   # darker accent: secondary borders, event stream
EMBER     = "#8a0015"   # deep-dark red: background tints
DIM_RED   = "#5c0a12"   # near-black red: very subtle elements

OFF_WHITE = "#e8e8e8"   # primary body text
DIM_GREY  = "#8a8a99"   # secondary labels, workspace name
MUTED     = "#5c5c6a"   # deep-muted: timestamps, hints

SUCCESS   = "#00cc66"   # confirmation green
WARNING   = "#ff8c00"   # amber warnings
INFO_BLUE = "#3fa8ff"   # informational accents

# ---------------------------------------------------------------------------
# Rich Style objects
# ---------------------------------------------------------------------------

S_PRIMARY = Style(color=NEON_RED, bold=True)
S_ACCENT  = Style(color=DEEP_RED, bold=True)
S_LABEL   = Style(color=OFF_WHITE, bold=True)
S_DIM     = Style(color=DIM_GREY, dim=True)
S_MUTED   = Style(color=MUTED)
S_SUCCESS = Style(color=SUCCESS, bold=True)
S_WARNING = Style(color=WARNING, bold=True)
S_INFO    = Style(color=INFO_BLUE)
S_BORDER  = Style(color=NEON_RED)

# ---------------------------------------------------------------------------
# Severity colour map
# ---------------------------------------------------------------------------

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: f"bold {NEON_RED}",
    Severity.HIGH:     "bold dark_orange",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "bold cyan",
    Severity.INFO:     f"dim {OFF_WHITE}",
}

# ---------------------------------------------------------------------------
# Confidence badges — a single visual language for reliability across surfaces
# ---------------------------------------------------------------------------
#
# Every confidence level maps to a fixed glyph + colour so a "high" replay looks
# the same in the workbench, the dashboard, and the report. Deterministic: same
# level always renders identically.

CONFIDENCE_GLYPHS: dict[str, str] = {
    "confirmed": "◆",
    "high": "●",
    "medium": "◐",
    "low": "○",
    "noise": "⊘",
}

CONFIDENCE_COLORS: dict[str, str] = {
    "confirmed": SUCCESS,
    "high": SUCCESS,
    "medium": WARNING,
    "low": DIM_GREY,
    "noise": MUTED,
}


def confidence_color(level: str) -> str:
    """Theme colour for a confidence level string (defaults to muted)."""
    return CONFIDENCE_COLORS.get(level, MUTED)


def confidence_badge(level: str, score: int | None = None, *, markup: bool = True) -> str:
    """Compact glyph + level (+ optional score) badge for a confidence level.

    With ``markup`` (default) returns Rich-markup coloured text; otherwise a plain
    ``"● high 82"`` string suitable for non-Rich surfaces.
    """
    glyph = CONFIDENCE_GLYPHS.get(level, "·")
    label = f"{glyph} {level}"
    if score is not None:
        label = f"{label} {score}"
    if not markup:
        return label
    return f"[{confidence_color(level)}]{label}[/]"


# ---------------------------------------------------------------------------
# Box types — cinematic HUD chrome character sets
# ---------------------------------------------------------------------------

HUD_BOX   = box.HEAVY       # thick solid lines — primary chrome
PANEL_BOX = box.DOUBLE      # double-line — secondary / replay panels
TABLE_BOX = box.HEAVY_HEAD  # heavy header row, light body — data tables

# ---------------------------------------------------------------------------
# Console singleton
# ---------------------------------------------------------------------------

console = Console()

# ---------------------------------------------------------------------------
# Text helpers — glow-style constructors
# ---------------------------------------------------------------------------


def glow(text: str) -> Text:
    """Neon-red bold — primary glow aesthetic."""
    return Text(text, style=S_PRIMARY)


def accent(text: str) -> Text:
    """Deep-red accent."""
    return Text(text, style=S_ACCENT)


def muted(text: str) -> Text:
    """Dim grey — timestamps, hints."""
    return Text(text, style=S_DIM)


def label(text: str) -> Text:
    """Off-white bold label."""
    return Text(text, style=S_LABEL)


# ---------------------------------------------------------------------------
# Status markers — the single house style for command output lines
# ---------------------------------------------------------------------------
#
# One consistent visual language for progress / success / failure / warning,
# modelled on professional offensive-security CLIs (sqlmap, nuclei, ffuf):
#
#     [*] in-progress / informational
#     [+] success
#     [-] failure / invalid input
#     [!] warning (e.g. optional dependency missing)
#
# Every command-facing status line goes through these so wording and colour are
# uniform across the whole app. They return Rich *markup strings* (not Text) so
# callers can embed further markup in the message.

def info(msg: str) -> str:
    """`[*]` informational / in-progress line."""
    return f"[bold {INFO_BLUE}]\\[*][/] {msg}"


def ok(msg: str) -> str:
    """`[+]` success line."""
    return f"[bold {SUCCESS}]\\[+][/] {msg}"


def err(msg: str) -> str:
    """`[-]` failure / invalid-input line."""
    return f"[bold {NEON_RED}]\\[-][/] {msg}"


def warn(msg: str) -> str:
    """`[!]` warning line (optional dependency missing, degraded mode, …)."""
    return f"[bold {WARNING}]\\[!][/] {msg}"


# ---------------------------------------------------------------------------
# Panel factories — reusable branded panels
#
# The compact REPL renders its banner/header/stats as plain left-aligned text
# (see spyder/ui/display.py), so the only Rich panels still in use are the two
# small detail panels below. The heavy full-width HUD/dashboard panel factories
# were removed with the Phase 2 UI redesign; the Textual dashboard styles itself
# via DASHBOARD_CSS, not these Rich helpers.
# ---------------------------------------------------------------------------


def secondary_panel(
    content,
    *,
    title: str = "",
    subtitle: str = "",
    padding: tuple[int, int] = (0, 1),
    width: int | None = None,
) -> Panel:
    """Secondary panel: double-line border."""
    return Panel(
        content,
        title=f"[bold {NEON_RED}]{title}[/]" if title else "",
        subtitle=f"[{DIM_GREY}]{subtitle}[/]" if subtitle else "",
        border_style=NEON_RED,
        box=PANEL_BOX,
        padding=padding,
        width=width,
    )


def replay_panel(content, *, title: str = "replay", idx: int | None = None) -> Panel:
    """Replay buffer transaction panel."""
    t = f"◈ replay · #{idx}" if idx is not None else f"◈ {title}"
    return Panel(
        content,
        title=f"[bold {NEON_RED}]{t}[/]",
        border_style=NEON_RED,
        box=PANEL_BOX,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Table factory
# ---------------------------------------------------------------------------


def base_table(title: str = "", *, expand: bool = False) -> Table:
    """Pre-styled Table with brand chrome and HEAVY_HEAD box.

    Titles are left-justified (not Rich's centered default) to match the compact,
    left-aligned house style of sqlmap/nuclei/ffuf output.
    """
    return Table(
        title=f"[bold {NEON_RED}]{title}[/]" if title else None,
        title_justify="left",
        border_style=NEON_RED,
        header_style=f"bold {OFF_WHITE}",
        box=TABLE_BOX,
        expand=expand,
    )


# ---------------------------------------------------------------------------
# HTML report structural colours (page bg, panel bg, rule lines)
# ---------------------------------------------------------------------------

BG       = "#0a0a0a"   # page background
PANEL_BG = "#111116"   # card / panel background
RULE     = "#24242c"   # rule / divider lines

# ---------------------------------------------------------------------------
# Reporting colour helpers
# ---------------------------------------------------------------------------

REPORT_SEVERITY_HEX: dict[str, str] = {
    "critical": NEON_RED,
    "high":     "#ff8c00",
    "medium":   "#ffcc00",
    "low":      "#00cccc",
    "info":     DIM_GREY,
}


def report_severity_style(severity: str) -> str:
    """Hex colour for a severity label used in HTML/PDF reports."""
    return REPORT_SEVERITY_HEX.get(severity.lower(), OFF_WHITE)


# Print / PDF override palette (white-on-white for paper rendering)
PRINT_BG    = "#ffffff"
PRINT_FG    = "#111111"
PRINT_PANEL = "#f5f5f5"
PRINT_RULE  = "#cccccc"
PRINT_CODE  = "#333333"

# Palette dict passed to Jinja2 report templates — the only place colors enter
# the HTML/PDF rendering pipeline.
HTML_PALETTE: dict = {
    "neon_red":    NEON_RED,
    "deep_red":    DEEP_RED,
    "ember":       EMBER,
    "bg":          BG,
    "panel_bg":    PANEL_BG,
    "rule":        RULE,
    "fg":          OFF_WHITE,
    "muted":       DIM_GREY,
    "subtle":      MUTED,
    "success":     SUCCESS,
    "warning":     WARNING,
    "severity":    REPORT_SEVERITY_HEX,
    "print_bg":    PRINT_BG,
    "print_fg":    PRINT_FG,
    "print_panel": PRINT_PANEL,
    "print_rule":  PRINT_RULE,
    "print_code":  PRINT_CODE,
}


# ---------------------------------------------------------------------------
# prompt_toolkit style dict — consumed by shell.py via Style.from_dict()
# ---------------------------------------------------------------------------

PROMPT_STYLE_DICT: dict[str, str] = {
    "prompt.spyder":  f"{NEON_RED} bold",
    "prompt.profile": INFO_BLUE,
    "prompt.ws":      DIM_GREY,
    "prompt.mode":    f"{WARNING} bold",
    "prompt.arrow":   f"{NEON_RED} bold",
}

# ---------------------------------------------------------------------------
# Textual CSS — constants for future Textual widget composition
# ---------------------------------------------------------------------------

TEXTUAL_CSS = f"""
Screen {{
    background: black;
    color: {OFF_WHITE};
}}

.hud-border {{
    border: heavy {NEON_RED};
    background: black;
}}

.panel-border {{
    border: double {NEON_RED};
    background: black;
}}

.hud-title {{
    color: {NEON_RED};
    text-style: bold;
}}

.hud-muted {{
    color: {DIM_GREY};
}}

.severity-critical {{
    color: {NEON_RED};
    text-style: bold;
}}

.severity-high {{
    color: {REPORT_SEVERITY_HEX["high"]};
    text-style: bold;
}}

.severity-medium {{
    color: {REPORT_SEVERITY_HEX["medium"]};
    text-style: bold;
}}

.severity-low {{
    color: {REPORT_SEVERITY_HEX["low"]};
    text-style: bold;
}}

.severity-info {{
    color: {DIM_GREY};
}}

.workspace-active {{
    color: {NEON_RED};
    text-style: bold;
}}

.workspace-inactive {{
    color: {DIM_GREY};
}}

.replay-panel {{
    border: double {NEON_RED};
    background: black;
}}

.event-stream {{
    border: double {DEEP_RED};
    background: black;
    color: {DIM_GREY};
}}

.plugin-list {{
    border: double {DEEP_RED};
    color: {OFF_WHITE};
}}

.dashboard-stat-label {{
    color: {OFF_WHITE};
    text-style: bold;
}}

.dashboard-stat-value {{
    color: {NEON_RED};
    text-style: bold;
}}

.success {{
    color: {SUCCESS};
    text-style: bold;
}}

.warning {{
    color: {WARNING};
    text-style: bold;
}}

.input-focused {{
    border: heavy {NEON_RED};
}}
"""

# ---------------------------------------------------------------------------
# Dashboard CSS — the persistent Textual SOC dashboard (single source of truth)
# Every colour is interpolated from the palette above; no literals here.
# ---------------------------------------------------------------------------

DASHBOARD_CSS = f"""
Screen {{
    background: {BG};
    color: {OFF_WHITE};
    layout: vertical;
}}

/* ── TOP HEADER ─────────────────────────────────────────────────────── */
#topbar {{
    height: 3;
    background: {PANEL_BG};
    color: {NEON_RED};
    border: heavy {NEON_RED};
    content-align: center middle;
    text-style: bold;
    padding: 0 1;
}}

/* ── BODY: three panes ──────────────────────────────────────────────── */
#body {{
    height: 1fr;
    layout: horizontal;
}}

#left-pane  {{ width: 28%; layout: vertical; }}
#center-pane {{ width: 1fr; layout: vertical; }}
#right-pane {{ width: 32%; layout: vertical; }}

/* ── HUD PANELS (Static) ────────────────────────────────────────────── */
.hud-panel {{
    border: round {NEON_RED};
    border-title-color: {NEON_RED};
    border-title-align: left;
    background: {PANEL_BG};
    color: {OFF_WHITE};
    padding: 0 1;
    height: auto;
    margin: 0 0 1 0;
}}

.hud-panel-accent {{
    border: round {DEEP_RED};
    border-title-color: {DEEP_RED};
    border-title-align: left;
    background: {PANEL_BG};
    color: {OFF_WHITE};
    padding: 0 1;
    height: auto;
    margin: 0 0 1 0;
}}

/* ── EVENT STREAM (left) ────────────────────────────────────────────── */
#event-stream {{
    height: 1fr;
    border: round {NEON_RED};
    border-title-color: {NEON_RED};
    border-title-align: left;
    background: {BG};
    color: {DIM_GREY};
    padding: 0 1;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}

/* ── CENTER / RIGHT scroll regions ──────────────────────────────────── */
#center-pane, #right-pane {{
    overflow-y: auto;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}

/* ── COMMAND OUTPUT (bottom) ────────────────────────────────────────── */
#command-output {{
    height: 10;
    border: round {DEEP_RED};
    border-title-color: {DEEP_RED};
    border-title-align: left;
    background: {BG};
    color: {OFF_WHITE};
    padding: 0 1;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}

/* ── FOOTER ─────────────────────────────────────────────────────────── */
#footer-bar {{
    height: 3;
    layout: horizontal;
    border: heavy {NEON_RED};
    background: {PANEL_BG};
}}

#cmd-input {{
    width: 1fr;
    background: {PANEL_BG};
    color: {OFF_WHITE};
    border: none;
    padding: 0 1;
}}
#cmd-input:focus {{
    background: {PANEL_BG};
    color: {OFF_WHITE};
}}

#status-bar {{
    width: auto;
    min-width: 36;
    color: {DIM_GREY};
    content-align: right middle;
    padding: 0 2;
}}
"""

# ---------------------------------------------------------------------------
# Event-type → colour mapping (for the dashboard event stream)
# ---------------------------------------------------------------------------

# Keyed by EventType.value to avoid importing the events module here (theme is a
# leaf dependency). The dashboard resolves colours via these string keys.
EVENT_COLORS: dict[str, str] = {
    "recon.start":     NEON_RED,
    "recon.done":      SUCCESS,
    "crawl.progress":  DIM_GREY,
    "endpoint.found":  OFF_WHITE,
    "param.probed":    INFO_BLUE,
    "fingerprint":     INFO_BLUE,
    "analyzer.done":   SUCCESS,
    "finding":         NEON_RED,
    "intel":           WARNING,
    "js.route":        INFO_BLUE,
    "secret":          NEON_RED,
    "connector.start": NEON_RED,
    "connector.done":  SUCCESS,
    "replay":          INFO_BLUE,
    "plugin":          WARNING,
    "subdomain":       OFF_WHITE,
    "recon.tool":      INFO_BLUE,
    "status":          DIM_GREY,
    "log":             DIM_GREY,
    "error":           NEON_RED,
}


def event_color(event_type: str) -> str:
    """Resolve a hex colour for an event-type value (EventType.value)."""
    return EVENT_COLORS.get(event_type, OFF_WHITE)


# ---------------------------------------------------------------------------
# Replay Workbench screen CSS (cyberpunk HUD, palette-sourced)
# ---------------------------------------------------------------------------

WORKBENCH_CSS = f"""
ReplayWorkbenchScreen {{
    background: {BG};
    color: {OFF_WHITE};
    layout: vertical;
}}

#wb-header {{
    height: 3;
    background: {PANEL_BG};
    color: {NEON_RED};
    border: heavy {NEON_RED};
    content-align: center middle;
    text-style: bold;
    padding: 0 1;
}}

#wb-body {{
    height: 1fr;
    layout: horizontal;
}}

#wb-list {{
    width: 30%;
    border: round {NEON_RED};
    border-title-color: {NEON_RED};
    border-title-align: left;
    background: {BG};
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}
#wb-list > ListItem {{
    background: {BG};
    color: {OFF_WHITE};
    padding: 0 1;
}}
#wb-list > ListItem.--highlight {{
    background: {EMBER};
    color: {OFF_WHITE};
    text-style: bold;
}}

#wb-center {{
    width: 1fr;
    layout: vertical;
}}
#wb-compare {{
    height: 40%;
    border: round {NEON_RED};
    border-title-color: {NEON_RED};
    border-title-align: left;
    background: {PANEL_BG};
    padding: 0 1;
    overflow-y: auto;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}
#wb-diff {{
    height: 1fr;
    border: round {DEEP_RED};
    border-title-color: {DEEP_RED};
    border-title-align: left;
    background: {BG};
    padding: 0 1;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}

#wb-right {{
    width: 30%;
    border: round {DEEP_RED};
    border-title-color: {DEEP_RED};
    border-title-align: left;
    background: {PANEL_BG};
    padding: 0 1;
    overflow-y: auto;
    scrollbar-color: {DEEP_RED};
    scrollbar-background: {BG};
}}

#wb-footer {{
    height: 3;
    layout: horizontal;
    border: heavy {NEON_RED};
    background: {PANEL_BG};
}}
#wb-input {{
    width: 1fr;
    background: {PANEL_BG};
    color: {OFF_WHITE};
    border: none;
    padding: 0 1;
}}
#wb-status {{
    width: auto;
    min-width: 30;
    color: {DIM_GREY};
    content-align: right middle;
    padding: 0 2;
}}
"""

# Sparkline glyphs for inline timing charts (low → high).
SPARK_GLYPHS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 32) -> str:
    """Render a list of numbers as a unicode sparkline string."""
    if not values:
        return ""
    series = values[-width:]
    lo, hi = min(series), max(series)
    span = (hi - lo) or 1.0
    n = len(SPARK_GLYPHS) - 1
    return "".join(SPARK_GLYPHS[int((v - lo) / span * n)] for v in series)
