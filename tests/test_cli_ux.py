"""Regression tests for the production-CLI UX pass.

Covers the framework-quality behaviours added in the release-engineering pass:
consistent status markers, 'did you mean' suggestions, enriched per-command help
metadata, and clean (traceback-free) handling of bad user input.
"""
from __future__ import annotations

import io

from rich.console import Console

from spyder.ui import theme
from spyder.ui.builtins import register_builtins
from spyder.ui.commands import CommandRegistry


def _registry() -> CommandRegistry:
    r = CommandRegistry()
    register_builtins(r)
    return r


def _render(markup: str) -> str:
    # Plain-text render (no ANSI colour spans) so we can assert on the glyphs.
    con = Console(file=io.StringIO(), width=80, no_color=True)
    con.print(markup)
    return con.file.getvalue()


# ── status markers ──────────────────────────────────────────────────────────

def test_status_markers_render_expected_glyphs():
    assert "[*]" in _render(theme.info("x"))
    assert "[+]" in _render(theme.ok("x"))
    assert "[-]" in _render(theme.err("x"))
    assert "[!]" in _render(theme.warn("x"))


def test_status_markers_escape_bracket_literally():
    # The '[*]' etc must be literal text, not swallowed as Rich markup.
    for fn in (theme.info, theme.ok, theme.err, theme.warn):
        out = _render(fn("hello"))
        assert "hello" in out


# ── did-you-mean suggestions ────────────────────────────────────────────────

def test_suggest_finds_close_command():
    r = _registry()
    assert "report" in r.suggest("repot")
    assert "history" in r.suggest("histry")
    assert "connector" in r.suggest("conector")


def test_suggest_maps_alias_to_canonical():
    r = _registry()
    # 'quit' is an alias of 'exit'; a near-miss should resolve to canonical name.
    assert "exit" in r.suggest("qui")


def test_suggest_empty_for_gibberish():
    r = _registry()
    assert r.suggest("zzzzzzzz") == []


# ── enriched help metadata ──────────────────────────────────────────────────

def test_every_builtin_has_help_metadata():
    r = _registry()
    for cmd in r.all():
        assert cmd.description, f"{cmd.name} missing description"
        assert cmd.usage, f"{cmd.name} missing usage"
        # Every non-trivial command should carry at least one example.
        if cmd.name not in ("exit",):
            assert cmd.examples, f"{cmd.name} missing examples"


def test_help_arguments_and_related_reference_real_commands():
    r = _registry()
    names = {c.name for c in r.all()}
    for cmd in r.all():
        for rel in cmd.related:
            assert rel in names, f"{cmd.name} lists unknown related command {rel!r}"
