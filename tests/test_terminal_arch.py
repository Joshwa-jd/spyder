"""Architecture-level regression tests for the unified terminal renderer.

These guard the invariants that a partially-applied refactor previously broke:
the CLI/REPL entry point (``spyder.__main__``) imported ``console``/``splash``
from ``spyder.ui.display`` after those symbols had been moved into the single
terminal owner ``spyder.ui.terminal`` — crashing every invocation at import,
before a single byte was ever rendered.

The rule these tests lock in: **every terminal primitive (the Rich console, the
banner, screen clear, terminal restore) has exactly one home — ``ui.terminal`` —
and nothing may resurrect a second copy or import a removed one.**
"""
from __future__ import annotations

import ast
import importlib
from pathlib import Path

from spyder.ui import display, terminal, theme

_SPYDER = Path(__file__).resolve().parent.parent / "spyder"


def test_entry_point_imports_cleanly():
    # The exact failure mode we fixed: importing the entry point must not raise.
    mod = importlib.import_module("spyder.__main__")
    importlib.reload(mod)
    assert hasattr(mod, "main")


def test_display_no_longer_exports_terminal_primitives():
    # display.py is content-only; the terminal chrome lives in terminal.py.
    for removed in ("console", "splash", "restore_terminal", "_banner"):
        assert not hasattr(display, removed), (
            f"display.{removed} was moved to ui.terminal — importing it re-splits "
            "terminal ownership and reintroduces the crash"
        )


def test_single_console_instance():
    # One Rich Console for the whole app: theme owns it, terminal re-exports it,
    # and nobody constructs their own.
    assert terminal.console is theme.console


def test_terminal_is_sole_owner_of_ansi_and_clear():
    """No source module outside ui/terminal.py may emit raw screen-control escape
    sequences or define its own screen clear/restore/banner."""
    offenders: list[str] = []
    for path in _SPYDER.rglob("*.py"):
        if path.name == "terminal.py":
            continue
        text = path.read_text(encoding="utf-8")
        # Raw alternate-screen / cursor / full-screen-clear control sequences.
        for needle in ("\\x1b[?1049", "\\x1b[2J", "\\x1b[3J", "\\x1b[H", "\\033["):
            if needle in text:
                offenders.append(f"{path.relative_to(_SPYDER)} emits {needle!r}")
    assert not offenders, "raw terminal-control sequences outside ui.terminal:\n" + "\n".join(offenders)


def test_exactly_one_promptsession():
    """The prompt is rendered in exactly one place (the REPL shell)."""
    hits = []
    for path in _SPYDER.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "PromptSession":
                hits.append(str(path.relative_to(_SPYDER)))
    assert hits == ["ui/shell.py"], f"PromptSession must be constructed only in ui/shell.py, found: {hits}"


def test_render_banner_clears_then_paints(monkeypatch):
    """render_banner routes through the one clear() (in ui.terminal) and then
    paints the one banner — so startup, `clear`, and dashboard exit are identical
    by construction."""
    from spyder.ui import banner

    calls: list[str] = []
    monkeypatch.setattr(terminal, "clear", lambda: calls.append("clear"))

    class _Con:
        def print(self, *a, **k):
            calls.append("print")

    con = _Con()
    banner.render_banner(con, clear_first=True)
    assert calls == ["clear", "print"]
    calls.clear()
    banner.render_banner(con, clear_first=False)
    assert calls == ["print"]  # clear_first=False skips the wipe (in-place paint)


def test_exactly_one_banner_implementation():
    """The banner is defined in exactly one place: ui/banner.py. No other module
    may resurrect a second banner renderable/function."""
    from spyder.ui import banner

    assert hasattr(banner, "render_banner") and hasattr(banner, "banner_renderable")
    # The removed terminal-level banner API must not come back.
    for gone in ("banner_group", "show_banner"):
        assert not hasattr(terminal, gone), (
            f"terminal.{gone} was moved into ui.banner — a second banner owner "
            "reintroduces the inconsistent-banner bug"
        )
    # Scan sources for stray banner definitions outside ui/banner.py.
    offenders = []
    for path in _SPYDER.rglob("*.py"):
        if path.name == "banner.py":
            continue
        text = path.read_text(encoding="utf-8")
        for needle in ("def render_banner", "def show_banner", "def banner_group", "ASCII_BANNER ="):
            if needle in text:
                offenders.append(f"{path.relative_to(_SPYDER)} defines {needle!r}")
    assert not offenders, "duplicate banner definitions:\n" + "\n".join(offenders)


def test_clear_sequence_homes_cursor_first():
    """The clear sequence must position the cursor at home (H) before/while wiping,
    so the banner is always repainted from row 1, col 1."""
    seq = terminal._CLEAR_SEQ
    assert seq.startswith("\x1b[H"), "clear must home the cursor (\\x1b[H) first"
    assert "\x1b[2J" in seq and "\x1b[3J" in seq  # wipe screen + scrollback
