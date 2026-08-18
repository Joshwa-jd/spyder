"""Regression tests for release-hardening fixes.

These lock in behaviour that previously crashed the REPL, leaked raw tracebacks,
or corrupted the terminal after the dashboard exited.
"""
from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from spyder.core.models import Target, normalize_url, parse_target
from spyder.ui.commands import Command, CommandRegistry

# --- target parsing (invalid input must never raise a raw ValidationError) ---

def test_normalize_url_adds_scheme_to_bare_host():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("https://example.com") == "https://example.com"
    assert normalize_url("  example.com  ") == "https://example.com"


def test_parse_target_accepts_real_targets():
    for raw in ("https://example.com", "example.com", "http://localhost:8080",
                "https://sub.example.co.uk/path?q=1"):
        t = parse_target(raw)
        assert isinstance(t, Target)


@pytest.mark.parametrize("bad", ["notaurl", "", "   ", "ftp://x.com"])
def test_parse_target_rejects_junk_with_clean_message(bad):
    with pytest.raises(ValueError) as ei:
        parse_target(bad)
    assert "Invalid target" in str(ei.value)
    # never leak a pydantic ValidationError to the operator
    assert "ValidationError" not in str(ei.value)


def test_parse_target_passes_scope_hosts():
    t = parse_target("example.com", ["a.example.com", "b.example.com"])
    assert t.scope_hosts == ["a.example.com", "b.example.com"]


# --- command dispatch must isolate handler failures (never kill the REPL) ---

def _ctx():
    console = SimpleNamespace(_out=[], print=lambda *a, **k: console._out.append(a))
    return SimpleNamespace(console=console)


async def test_dispatch_survives_handler_exception():
    reg = CommandRegistry()

    async def boom(ctx, args):
        raise RuntimeError("kaboom")

    reg.register(Command("boom", "explodes", boom))
    ctx = _ctx()
    keep_going = await reg.dispatch(ctx, "boom")
    assert keep_going is True  # REPL continues
    printed = " ".join(str(a) for tup in ctx.console._out for a in tup)
    assert "error" in printed and "kaboom" in printed


async def test_dispatch_unknown_command_is_graceful():
    reg = CommandRegistry()
    ctx = _ctx()
    assert await reg.dispatch(ctx, "nope") is True
    printed = " ".join(str(a) for tup in ctx.console._out for a in tup)
    assert "unknown command" in printed


async def test_dispatch_exit_returns_false():
    reg = CommandRegistry()

    async def noop(ctx, args):
        return None

    reg.register(Command("exit", "quit", noop))
    assert await reg.dispatch(_ctx(), "exit") is False


# --- terminal restoration (dashboard exit / clear) ---

class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def test_restore_terminal_emits_reset_sequences(monkeypatch):
    from spyder.ui import terminal
    fake = _FakeTTY()
    monkeypatch.setattr(terminal.sys, "stdout", fake)
    terminal.restore()
    out = fake.getvalue()
    assert "\x1b[?1049l" in out   # exit alternate screen
    assert "\x1b[?25h" in out     # show cursor
    assert "\x1b[?1006l" in out   # disable SGR mouse tracking


def test_hard_clear_wipes_scrollback(monkeypatch):
    from spyder.ui import terminal
    fake = _FakeTTY()
    monkeypatch.setattr(terminal.sys, "stdout", fake)
    terminal.clear()
    out = fake.getvalue()
    assert "\x1b[3J" in out        # clear scrollback
    assert "\x1b[H" in out         # cursor homed to row 1, col 1
    assert "\x1b[?1049l" in out    # also restores terminal first


# --- scan history dedups by (kind, target) even when runs are interleaved ---

def test_log_scan_dedups_interleaved_runs(tmp_path):
    from spyder.workspace.manager import WorkspaceManager

    wm = WorkspaceManager(tmp_path / "ws.sqlite")
    try:
        wid = wm.create("w")
        wm.log_scan(wid, "recon", "s1", target="http://a", endpoints=5)
        wm.log_scan(wid, "nuclei", "s2", target="http://a")     # different activity
        wm.log_scan(wid, "recon", "s3", target="http://a", endpoints=9)  # re-run recon
        wm.log_scan(wid, "recon", "sB", target="http://b")      # distinct target

        rows = wm.history(wid)
        recon_a = [r for r in rows if r["kind"] == "recon" and r["target"] == "http://a"]
        assert len(recon_a) == 1                 # not duplicated by the nuclei run between
        assert recon_a[0]["summary"] == "s3"     # refreshed to the latest run
        assert recon_a[0]["endpoints"] == 9
        assert len(rows) == 3                    # recon/a, nuclei/a, recon/b
    finally:
        wm.close()


# --- path traversal: operator-supplied names must not escape their directory ---

def test_safe_slug_neutralizes_traversal():
    from spyder.utils.paths import safe_slug

    assert safe_slug("../../../../tmp/PWNED") == "tmp_PWNED"
    assert safe_slug("a/b/c") == "a_b_c"
    assert safe_slug("..\\..\\evil") == "evil"
    assert safe_slug("..") == "default"
    assert safe_slug("") == "default"
    assert safe_slug("   ") == "default"
    # normal names pass through unchanged
    assert safe_slug("acme-2024") == "acme-2024"
    # no path separator or leading dot can survive
    for bad in ("../x", "/etc/passwd", "..", "./.."):
        out = safe_slug(bad)
        assert "/" not in out and "\\" not in out and not out.startswith(".")


def test_report_export_cannot_escape_out_dir(tmp_path):
    from spyder.reporting.engine import ReportEngine

    out = tmp_path / "reports"
    eng = ReportEngine()
    p = eng.export("json", "../../../../tmp/PWNED", "t", [], out)
    assert str(p.resolve()).startswith(str(out.resolve()))
    assert not (tmp_path.parent / "tmp" / "PWNED").exists()


def test_workspace_dir_cannot_escape_workspaces_dir(tmp_path):
    from spyder.workspace.layout import WorkspacePaths

    wsdir = tmp_path / "workspaces"
    wp = WorkspacePaths.for_workspace(wsdir, "../../../../tmp/PWN").ensure()
    assert str(wp.root.resolve()).startswith(str(wsdir.resolve()))


# --- concurrent DB access (dashboard + REPL) must not deadlock on SQLite ---

def test_workspace_db_uses_wal_and_survives_concurrent_writers(tmp_path):
    import sqlite3

    from spyder.core.models import Finding, Severity
    from spyder.workspace.manager import WorkspaceManager

    db = tmp_path / "c.sqlite"
    a = WorkspaceManager(db)
    b = WorkspaceManager(db)  # second connection, like the dashboard opening its own
    try:
        assert a.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        wa = a.create("w")
        wb = b.get_id("w")
        errors = 0
        for i in range(100):
            m, wid = (a, wa) if i % 2 == 0 else (b, wb)
            try:
                m.save_finding(wid, Finding(title=f"f{i}", severity=Severity.INFO, source=f"s{i}"))
            except sqlite3.OperationalError:
                errors += 1
        assert errors == 0
    finally:
        a.close()
        b.close()


# --- unknown connector raises a clean ValueError (not KeyError with quotes) ---

def test_unknown_connector_message_is_clean(tmp_path):
    from spyder.core.config import SpyderConfig
    from spyder.core.orchestrator import Orchestrator

    cfg = SpyderConfig(home=tmp_path)
    cfg.ensure_dirs()
    orch = Orchestrator(cfg, "t")
    try:
        import asyncio
        with pytest.raises(ValueError) as ei:
            asyncio.run(orch.run_connector("doesnotexist", "https://example.com", {}))
        msg = str(ei.value)
        assert "No connector named" in msg
        assert not msg.startswith('"')  # KeyError-style quote wrapping is gone
    finally:
        orch.close()
