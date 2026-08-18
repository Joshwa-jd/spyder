"""Regression tests for workspace command semantics (PAT findings)."""
from __future__ import annotations

import io

import pytest
from rich.console import Console

from spyder.core.config import SpyderConfig
from spyder.core.orchestrator import Orchestrator
from spyder.ui.builtins import _cmd_workspace
from spyder.ui.commands import CommandRegistry
from spyder.ui.shell import ShellContext


@pytest.fixture
def ctx(tmp_path):
    cfg = SpyderConfig(home=tmp_path, profile_name="default")
    cfg.ensure_dirs()
    orch = Orchestrator(cfg, "default")
    buf = io.StringIO()
    rec = Console(file=buf, width=100, force_terminal=False)
    c = ShellContext(config=cfg, orch=orch, registry=CommandRegistry(),
                     workspace="default", console=rec)
    c._buf = buf  # type: ignore[attr-defined]
    yield c
    c.orch.close()


def _out(ctx) -> str:
    return ctx._buf.getvalue()  # type: ignore[attr-defined]


async def test_use_nonexistent_workspace_errors_and_does_not_create(ctx):
    before = {w["name"] for w in ctx.orch.wm.list_workspaces()}
    await _cmd_workspace(ctx, ["use", "does-not-exist"])
    after = {w["name"] for w in ctx.orch.wm.list_workspaces()}
    # It must NOT silently create the workspace...
    assert "does-not-exist" not in after
    assert after == before
    # ...and must not have switched.
    assert ctx.workspace == "default"
    # ...and must tell the user how to fix it.
    out = _out(ctx)
    assert "no such workspace" in out
    assert "workspace new" in out


async def test_use_existing_workspace_switches(ctx):
    await _cmd_workspace(ctx, ["new", "acme"])
    ctx._buf.truncate(0)  # type: ignore[attr-defined]
    ctx._buf.seek(0)  # type: ignore[attr-defined]
    await _cmd_workspace(ctx, ["use", "acme"])
    assert ctx.workspace == "acme"
    assert "switched to workspace" in _out(ctx)


async def test_new_then_findings_isolated_per_workspace(ctx):
    # A fresh workspace starts empty; switching does not leak the other's records.
    await _cmd_workspace(ctx, ["new", "ws-a"])
    assert ctx.orch.findings() == []
    await _cmd_workspace(ctx, ["new", "ws-b"])
    assert ctx.orch.findings() == []
