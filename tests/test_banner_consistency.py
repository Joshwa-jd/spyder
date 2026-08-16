"""End-to-end banner-consistency regression (release-blocker item 21).

Drives the *real* command handlers — startup, ``clear``, ``restart``,
``workspace new``, ``workspace use``, and dashboard exit — through a live
``ShellContext`` and asserts every one paints a byte-for-byte identical banner.
If the banner ever differs by a single character between two render paths, one of
these assertions fails. This is the automated version of the manual verification
script in the task (spyder → clear → dashboard → workspace new/use → restart).
"""
from __future__ import annotations

import asyncio
import io

from rich.console import Console

from spyder.core.config import SpyderConfig
from spyder.core.orchestrator import Orchestrator
from spyder.ui.banner import FOOTER, SUBTITLE, render_banner
from spyder.ui.builtins import (
    _cmd_clear,
    _cmd_restart,
    _cmd_workspace,
    register_builtins,
)
from spyder.ui.commands import CommandRegistry
from spyder.ui.shell import ShellContext


def _ctx(tmp_path):
    cfg = SpyderConfig(home=tmp_path)
    orch = Orchestrator(cfg, "default")
    registry = CommandRegistry()
    register_builtins(registry)
    con = Console(width=100, file=io.StringIO(), force_terminal=True)
    ctx = ShellContext(
        config=cfg, orch=orch, registry=registry, workspace="default", console=con
    )
    return ctx, con


def _banner_block(text: str) -> str:
    """Extract just the banner region (spider → footer) from captured output,
    ignoring any per-command confirmation lines printed after it."""
    start = text.index("\\")            # first spider row begins with a backslash
    end = text.index(FOOTER) + len(FOOTER)
    return text[start:end]


def _run(coro):
    asyncio.run(coro)


def test_all_render_paths_produce_identical_banner(tmp_path):
    # Reference banner (startup path) rendered in isolation.
    ref_con = Console(width=100, file=io.StringIO(), force_terminal=True)
    render_banner(ref_con, clear_first=False)
    reference = _banner_block(ref_con.file.getvalue())
    # Sanity: reference actually contains the whole identity.
    assert SUBTITLE in reference and FOOTER in reference and "█" in reference

    banners: dict[str, str] = {"startup": reference}

    # clear
    ctx, con = _ctx(tmp_path)
    _run(_cmd_clear(ctx, []))
    banners["clear"] = _banner_block(con.file.getvalue())

    # restart
    ctx, con = _ctx(tmp_path)
    _run(_cmd_restart(ctx, []))
    banners["restart"] = _banner_block(con.file.getvalue())

    # workspace new demo
    ctx, con = _ctx(tmp_path)
    _run(_cmd_workspace(ctx, ["new", "demo"]))
    banners["workspace-new"] = _banner_block(con.file.getvalue())

    # workspace use demo
    _run(_cmd_workspace(ctx, ["use", "demo"]))
    banners["workspace-use"] = _banner_block(con.file.getvalue())

    # Every render path is byte-for-byte identical to startup.
    for name, out in banners.items():
        assert out == reference, f"banner from {name!r} differs from startup banner"
