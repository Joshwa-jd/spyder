"""Replay Workbench — a full-screen analyst surface for request/response analysis.

Pushed on top of the dashboard (binding ctrl+w or command `workbench`). Presents:
  * a selectable replay history list (left)
  * side-by-side request/response comparison + a unified body diff (center)
  * replay analytics with a timing sparkline (right)
  * a command line for bookmarking, tagging, notes, grouping, and diff/syntax toggle

Read-only analysis: it inspects and annotates replays the analyst already issued.
All colour comes from spyder.ui.theme.
"""
from __future__ import annotations

import difflib
import shlex
from typing import TYPE_CHECKING

from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, ListItem, ListView, Static

from ..analysis.replay import ReplayAnalytics, ReplayRecord
from ..validation.replay import normalize_diff_lines
from . import theme
from .theme import (
    DIM_GREY,
    INFO_BLUE,
    MUTED,
    NEON_RED,
    OFF_WHITE,
    SUCCESS,
    WARNING,
    confidence_badge,
    confidence_color,
)

if TYPE_CHECKING:  # avoid import cycle with dashboard
    from .dashboard import DashboardController


# ---------------------------------------------------------------------------
# Renderable builders
# ---------------------------------------------------------------------------


def _lexer_for(content_type: str | None) -> str:
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct or "xml" in ct:
        return "html"
    if "javascript" in ct or "ecmascript" in ct:
        return "javascript"
    if "css" in ct:
        return "css"
    return "text"


def render_compare(record: ReplayRecord) -> Table:
    """Side-by-side original vs replayed request/response comparison."""
    o, r = record.original, record.replayed
    t = Table.grid(expand=True, padding=(0, 1, 0, 0))
    t.add_column(justify="left", width=14)
    t.add_column(justify="left", ratio=1)
    t.add_column(justify="left", ratio=1)
    t.add_row(f"[{DIM_GREY}]field[/]", f"[{OFF_WHITE}]original[/]", f"[{NEON_RED}]replayed[/]")

    def row(label, a, b, changed=False):
        bc = NEON_RED if changed else OFF_WHITE
        t.add_row(f"[{DIM_GREY}]{label}[/]", f"[{DIM_GREY}]{a}[/]", f"[{bc}]{b}[/]")

    # Confidence indicator first — it tells the analyst how much to trust the diff.
    badge = confidence_badge(record.confidence_level, record.confidence_score)
    stability = "stable" if record.stable else ("anomalous" if record.anomalous else "—")
    t.add_row(f"[{DIM_GREY}]confidence[/]", badge,
              f"[{confidence_color(record.confidence_level)}]{stability}[/]")

    if not o or not r:
        t.add_row(f"[{MUTED}]no snapshot[/]", "", "")
        return t

    row("status", o.status, r.status, record.status_changed)
    row("timing ms", f"{o.elapsed_ms:.0f}", f"{r.elapsed_ms:.0f}",
        abs(record.timing_delta_ms) > 250)
    row("body len", o.body_len, r.body_len, record.length_delta != 0)
    row("content", o.content_type or "—", r.content_type or "—")
    row("similarity", "", f"{record.similarity}")
    if record.redirected:
        row("redirect", record.redirect_from or "—", record.redirect_to or "—", True)
    if record.reflected:
        row("reflected", "", ", ".join(record.reflected[:6]), True)

    # response header mutations
    hd = record.resp_header_diff
    if not hd.empty:
        t.add_row("", "", "")
        t.add_row(f"[{WARNING}]hdr Δ[/]", "", "")
        for k, v in hd.added[:6]:
            t.add_row(f"[{SUCCESS}]+ {k}[/]", "", f"[{DIM_GREY}]{v}[/]")
        for k, v in hd.removed[:6]:
            t.add_row(f"[{NEON_RED}]- {k}[/]", f"[{DIM_GREY}]{v}[/]", "")
        for k, old, new in hd.changed[:6]:
            t.add_row(f"[{WARNING}]~ {k}[/]", f"[{DIM_GREY}]{old}[/]", f"[{OFF_WHITE}]{new}[/]")

    # Evidence trace — *why* the replay scored as it did (traceability).
    if record.anomalies:
        t.add_row("", "", "")
        t.add_row(f"[{WARNING}]anomalies[/]",
                  f"[{WARNING}]{', '.join(record.anomalies)}[/]", "")
    if record.confidence_reasons:
        t.add_row(f"[{DIM_GREY}]evidence[/]", "", "")
        for reason in record.confidence_reasons[:8]:
            t.add_row("", f"[{MUTED}]· {reason}[/]", "")
    return t


def render_body_diff(record: ReplayRecord, *, normalize: bool = True) -> Text:
    """Unified diff of original vs replayed response bodies, neon-coloured.

    With ``normalize`` (default) volatile spans — timestamps, ids, nonces — are
    masked first, so the diff shows only *meaningful* changes rather than per-
    request noise. Toggle it off to inspect the raw bytes.
    """
    o, r = record.original, record.replayed
    if not o or not r:
        return Text("no body snapshot", style=MUTED)
    if normalize:
        a = normalize_diff_lines(o.body_preview)
        b = normalize_diff_lines(r.body_preview)
    else:
        a = o.body_preview.splitlines()
        b = r.body_preview.splitlines()
    if a == b:
        msg = "identical response bodies (after noise normalization)" if normalize else "identical response bodies"
        return Text(msg, style=DIM_GREY)
    out = Text()
    for line in difflib.unified_diff(a, b, lineterm="", n=2,
                                     fromfile="original", tofile="replayed"):
        if line.startswith("+") and not line.startswith("+++"):
            out.append(line + "\n", style=SUCCESS)
        elif line.startswith("-") and not line.startswith("---"):
            out.append(line + "\n", style=NEON_RED)
        elif line.startswith("@@"):
            out.append(line + "\n", style=INFO_BLUE)
        else:
            out.append(line + "\n", style=DIM_GREY)
    return out


def render_body_syntax(record: ReplayRecord) -> Syntax | Text:
    """Syntax-highlighted view of the replayed body."""
    r = record.replayed
    if not r or not r.body_preview:
        return Text("no body", style=MUTED)
    return Syntax(
        r.body_preview, _lexer_for(r.content_type),
        theme="monokai", word_wrap=True, line_numbers=False,
    )


def render_wb_analytics(analytics: ReplayAnalytics, record: ReplayRecord | None) -> Table:
    a = analytics
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(justify="left", ratio=1)
    g.add_column(justify="right")
    if a.empty:
        g.add_row(f"[{MUTED}]no replays yet[/]", "")
        return g

    def kv(k, v, c=NEON_RED):
        g.add_row(f"[{DIM_GREY}]{k}[/]", f"[{c}]{v}[/]")

    stab_color = SUCCESS if a.stability_pct >= 70 else WARNING if a.stability_pct >= 40 else NEON_RED
    kv("replays", a.total)
    kv("stable", f"{a.stable}/{a.total} · {a.stability_pct:.0f}%", stab_color)
    kv("anomalous", a.anomalous, WARNING if a.anomalous else DIM_GREY)
    kv("avg confidence", f"{a.avg_confidence:.0f}", OFF_WHITE)
    kv("bookmarked", a.bookmarked, WARNING)
    kv("status changes", a.status_changes, WARNING)
    kv("redirects", a.redirects)
    kv("with reflection", a.with_reflection, WARNING)
    kv("avg timing", f"{a.avg_timing_ms:.0f}ms")
    kv("min / max", f"{a.min_timing_ms:.0f}/{a.max_timing_ms:.0f}ms", OFF_WHITE)
    kv("avg similarity", a.avg_similarity, OFF_WHITE)

    g.add_row("", "")
    g.add_row(f"[{DIM_GREY}]timing[/]", "")
    g.add_row(f"[{INFO_BLUE}]{theme.sparkline(a.timing_series, 26)}[/]", "")
    if a.confidence_series:
        g.add_row(f"[{DIM_GREY}]confidence[/]", "")
        g.add_row(f"[{SUCCESS}]{theme.sparkline([float(c) for c in a.confidence_series], 26)}[/]", "")

    if a.anomaly_counts:
        g.add_row("", "")
        g.add_row(f"[{WARNING}]anomalies[/]", "")
        for kind, n in sorted(a.anomaly_counts.items(), key=lambda kv: kv[1], reverse=True):
            g.add_row(f"[{OFF_WHITE}]{kind}[/]", f"[{WARNING}]{n}[/]")

    if a.status_distribution:
        g.add_row("", "")
        g.add_row(f"[{DIM_GREY}]status flow[/]", "")
        for flow, n in sorted(a.status_distribution.items(), key=lambda kv: kv[1], reverse=True)[:6]:
            g.add_row(f"[{OFF_WHITE}]{flow}[/]", f"[{NEON_RED}]{n}[/]")

    if record:
        g.add_row("", "")
        g.add_row(f"[{DIM_GREY}]selected[/]", "")
        tags = ", ".join(record.tags) or "—"
        g.add_row(f"[{DIM_GREY}]tags[/]", f"[{WARNING}]{tags}[/]")
        g.add_row(f"[{DIM_GREY}]mark[/]", f"[{NEON_RED}]{'★' if record.bookmarked else '—'}[/]")
        if record.note:
            g.add_row(f"[{DIM_GREY}]note[/]", f"[{OFF_WHITE}]{record.note[:40]}[/]")
    return g


def render_replay_timeline(records: list[ReplayRecord], limit: int = 16) -> Table:
    """Chronological replay activity timeline — one row per replay, newest first."""
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(justify="left", width=3)   # marker
    g.add_column(justify="left", width=9)   # clock
    g.add_column(justify="left", ratio=1)   # method + url
    g.add_column(justify="right")           # status flow
    if not records:
        g.add_row("", "", f"[{MUTED}]no replay activity yet[/]", "")
        return g
    # newest first for an activity feed, but ordering is by deterministic id
    ordered = sorted(records, key=lambda r: r.id)[-limit:][::-1]
    for r in ordered:
        cc = confidence_color(r.confidence_level)
        flow_color = WARNING if r.status_changed else DIM_GREY
        url = r.url.split("://")[-1]
        if len(url) > 36:
            url = url[:35] + "…"
        g.add_row(
            f"[{cc}]{r.marker}[/]",
            f"[{MUTED}]{r.clock}[/]",
            f"[{DIM_GREY}]#{r.id}[/] [{OFF_WHITE}]{r.method}[/] {url}",
            f"[{flow_color}]{r.status_flow}[/]",
        )
    return g


def _list_label(record: ReplayRecord) -> str:
    mark = "★" if record.bookmarked else " "
    flip = "≠" if record.status_changed else "="
    rfl = "⮌" if record.redirected else (" " if not record.reflected else "⊚")
    cc = confidence_color(record.confidence_level)
    glyph = theme.CONFIDENCE_GLYPHS.get(record.confidence_level, "·")
    url = record.url.split("://")[-1]
    if len(url) > 30:
        url = url[:29] + "…"
    return (f"[{NEON_RED}]{mark}[/] [{cc}]{glyph}[/] [{DIM_GREY}]#{record.id}[/] "
            f"{record.method} [{OFF_WHITE}]{record.replayed_status}[/]{flip}{rfl} {url}")


# ---------------------------------------------------------------------------
# The screen
# ---------------------------------------------------------------------------

_WB_HELP = (
    "[b]workbench[/]  ↑/↓ select · bookmark · tag <t> · note <text> · group <g> · "
    "search <q> · syntax/diff/norm · back"
)


class ReplayWorkbenchScreen(Screen):
    """Full-screen replay & request analysis workbench."""

    CSS = theme.WORKBENCH_CSS
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("ctrl+w", "app.pop_screen", "Back"),
        ("s", "toggle_syntax", "Syntax/Diff"),
        ("b", "toggle_bookmark", "Bookmark"),
        ("n", "toggle_normalize", "Normalize"),
    ]

    def __init__(self, controller: DashboardController) -> None:
        super().__init__()
        self.controller = controller
        self._records: list[ReplayRecord] = []
        self._show_syntax = False
        self._normalize_diff = True
        self._query = ""

    def compose(self):
        yield Static(id="wb-header")
        with Horizontal(id="wb-body"):
            yield ListView(id="wb-list")
            with Vertical(id="wb-center"):
                yield VerticalScroll(Static(id="wb-compare"), id="wb-compare-pane")
                yield VerticalScroll(Static(id="wb-diff"), id="wb-diff-pane")
            yield VerticalScroll(Static(id="wb-right"), id="wb-right-pane")
        with Horizontal(id="wb-footer"):
            yield Input(placeholder="workbench>  bookmark · tag <t> · note <text> · group <g> · search <q> · syntax/norm · back", id="wb-input")
            yield Static(id="wb-status")

    def on_mount(self) -> None:
        self.query_one("#wb-list", ListView).border_title = "◢ REPLAY HISTORY ◣"
        self.query_one("#wb-compare-pane", VerticalScroll).border_title = "◢ REQUEST / RESPONSE COMPARE ◣"
        self.query_one("#wb-diff-pane", VerticalScroll).border_title = "◢ BODY DIFF ◣"
        self.query_one("#wb-right-pane", VerticalScroll).border_title = "◢ REPLAY ANALYTICS ◣"
        self._reload()
        self.query_one("#wb-header", Static).update(
            f"[b {NEON_RED}]◢ SPYDER REPLAY WORKBENCH ◣[/]  [{DIM_GREY}]"
            f"workspace[/] [{OFF_WHITE}]{self.controller.workspace}[/]"
        )
        self.query_one("#wb-status", Static).update(_WB_HELP)
        self.query_one("#wb-list", ListView).focus()

    def _visible_records(self) -> list[ReplayRecord]:
        """Replay records (newest first) after applying the active search filter."""
        recs = list(reversed(self.controller.orch.replay_records()))
        if self._query:
            recs = [r for r in recs if r.matches(self._query)]
        return recs

    def _reload(self) -> None:
        self._records = self._visible_records()
        lv = self.query_one("#wb-list", ListView)
        lv.clear()
        for rec in self._records:
            lv.append(ListItem(Static(_list_label(rec))))
        if self._records:
            lv.index = 0
            self._render_detail(self._records[0])
        else:
            self.query_one("#wb-compare", Static).update(
                Text("no replays yet — run 'replay <#>' on the dashboard first", style=MUTED)
            )
            self.query_one("#wb-diff", Static).update(Text("", style=MUTED))
            self.query_one("#wb-right", Static).update(
                render_wb_analytics(self.controller.orch.replay_analytics(), None)
            )

    def _current(self) -> ReplayRecord | None:
        idx = self.query_one("#wb-list", ListView).index
        if idx is not None and 0 <= idx < len(self._records):
            return self._records[idx]
        return None

    def _render_detail(self, record: ReplayRecord) -> None:
        self.query_one("#wb-compare", Static).update(render_compare(record))
        if self._show_syntax:
            self.query_one("#wb-diff", Static).update(render_body_syntax(record))
        else:
            self.query_one("#wb-diff", Static).update(
                render_body_diff(record, normalize=self._normalize_diff)
            )
        self.query_one("#wb-right", Static).update(
            render_wb_analytics(self.controller.orch.replay_analytics(), record)
        )

    # --- events ---
    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        rec = self._current()
        if rec:
            self._render_detail(rec)

    def action_toggle_syntax(self) -> None:
        self._show_syntax = not self._show_syntax
        rec = self._current()
        if rec:
            self._render_detail(rec)

    def action_toggle_normalize(self) -> None:
        self._normalize_diff = not self._normalize_diff
        self._show_syntax = False
        rec = self._current()
        if rec:
            self._render_detail(rec)
        self.query_one("#wb-status", Static).update(
            f"[{SUCCESS}]diff normalization {'on' if self._normalize_diff else 'off'}[/]"
        )

    def action_toggle_bookmark(self) -> None:
        rec = self._current()
        if rec:
            self.controller.orch.replay_bookmark(rec.id, not rec.bookmarked)
            self._refresh_keep_position()

    def _refresh_keep_position(self) -> None:
        idx = self.query_one("#wb-list", ListView).index or 0
        self._records = self._visible_records()
        lv = self.query_one("#wb-list", ListView)
        lv.clear()
        for rec in self._records:
            lv.append(ListItem(Static(_list_label(rec))))
        if self._records:
            lv.index = min(idx, len(self._records) - 1)
            self._render_detail(self._records[lv.index])

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        line = message.value.strip()
        self.query_one("#wb-input", Input).value = ""
        if not line:
            return
        rec = self._current()
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        status = self.query_one("#wb-status", Static)

        if cmd in ("back", "q", "quit", "exit"):
            self.app.pop_screen()
        elif cmd in ("syntax", "diff"):
            self._show_syntax = cmd == "syntax"
            if rec:
                self._render_detail(rec)
        elif cmd in ("norm", "normalize", "raw"):
            self._normalize_diff = cmd != "raw"
            self._show_syntax = False
            if rec:
                self._render_detail(rec)
            status.update(f"[{SUCCESS}]diff normalization {'on' if self._normalize_diff else 'off'}[/]")
        elif cmd in ("search", "filter", "find"):
            self._query = " ".join(args)
            self._reload()
            shown = len(self._records)
            label = f"'{self._query}' → {shown}" if self._query else "cleared"
            status.update(f"[{INFO_BLUE}]filter {label}[/]")
        elif cmd in ("clear", "reset") and not args:
            self._query = ""
            self._reload()
            status.update(f"[{SUCCESS}]filter cleared[/]")
        elif rec is None:
            status.update(f"[{NEON_RED}]no record selected[/]")
        elif cmd == "bookmark":
            self.controller.orch.replay_bookmark(rec.id, not rec.bookmarked)
            self._refresh_keep_position()
            status.update(f"[{SUCCESS}]bookmark toggled #{rec.id}[/]")
        elif cmd == "tag" and args:
            self.controller.orch.replay_tag(rec.id, *args)
            self._refresh_keep_position()
            status.update(f"[{SUCCESS}]tagged #{rec.id}[/]")
        elif cmd == "note" and args:
            self.controller.orch.replay_note(rec.id, " ".join(args))
            self._render_detail(rec)
            status.update(f"[{SUCCESS}]note saved #{rec.id}[/]")
        elif cmd == "group" and args:
            self.controller.orch.replay_group(rec.id, " ".join(args))
            status.update(f"[{SUCCESS}]grouped #{rec.id}[/]")
        else:
            status.update(f"[{NEON_RED}]usage:[/] bookmark · tag <t> · note <text> · group <g> · search <q> · syntax/diff/norm/raw · back")
