"""Round 8: the dashboard must show the workspace it was opened on, and only that.

A dashboard that renders a stale or borrowed value is worse than one that
renders nothing: the operator has no way to tell which workspace they are
looking at, and the number is confident either way.
"""
from __future__ import annotations

import pytest

from spyder.core.config import SpyderConfig
from spyder.core.models import Endpoint, Finding, Severity
from spyder.ui.dashboard import DashboardController, SpyderDashboard


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    c = SpyderConfig()
    c.home = tmp_path
    return c


def _screen_text(app) -> str:
    """Everything actually painted, as plain text.

    Read off the compositor rather than off the widgets: this is what the
    operator sees, so a value that never reaches the screen cannot pass.
    """
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(seg.text for seg in strip) for strip in strips)


def _seed(config, workspace: str, titles: list[str], urls: list[str]) -> None:
    """Put known findings and endpoints into a workspace, then close it."""
    ctl = DashboardController(config, workspace=workspace)
    try:
        for t in titles:
            ctl.orch.wm.save_finding(
                ctl.orch.ws_id,
                Finding(title=t, severity=Severity.HIGH, endpoint=urls[0] if urls else ""),
            )
        if urls:
            ctl.orch.wm.save_endpoints(ctl.orch.ws_id, [Endpoint(url=u) for u in urls])
    finally:
        ctl.close()


def test_controller_reads_the_workspace_it_was_opened_on(config):
    _seed(config, "alpha", ["Alpha finding"], ["http://alpha.test/a"])
    _seed(config, "beta", ["Beta finding"], ["http://beta.test/b"])

    ctl = DashboardController(config, workspace="alpha")
    try:
        snap = ctl.snapshot()
    finally:
        ctl.close()

    titles = [f.title for f in snap.findings]
    assert "Alpha finding" in titles
    assert "Beta finding" not in titles, "workspace alpha is showing beta's findings"


def test_a_second_dashboard_does_not_inherit_the_first_workspace_state(config):
    """Regression guard for stale state across launch cycles."""
    _seed(config, "alpha", ["Alpha finding"], ["http://alpha.test/a"])
    _seed(config, "beta", [], [])

    first = DashboardController(config, workspace="alpha")
    try:
        assert first.snapshot().findings
    finally:
        first.close()

    second = DashboardController(config, workspace="beta")
    try:
        snap = second.snapshot()
    finally:
        second.close()

    assert [f.title for f in snap.findings] == [], (
        f"empty workspace inherited {[f.title for f in snap.findings]}"
    )
    assert snap.endpoints == []


def test_repeated_snapshots_of_an_unchanged_workspace_are_equal(config):
    """No drift and no accumulation from merely looking at it."""
    _seed(config, "alpha", ["Alpha finding"], ["http://alpha.test/a"])
    ctl = DashboardController(config, workspace="alpha")
    try:
        first = ctl.snapshot()
        for _ in range(5):
            again = ctl.snapshot()
            assert [f.title for f in again.findings] == [f.title for f in first.findings]
            assert len(again.endpoints) == len(first.endpoints)
    finally:
        ctl.close()


def test_snapshot_picks_up_a_finding_written_after_launch(config):
    """The dashboard is live: a value written while it is open must appear."""
    ctl = DashboardController(config, workspace="alpha")
    try:
        assert ctl.snapshot().findings == []
        ctl.orch.wm.save_finding(
            ctl.orch.ws_id, Finding(title="Arrived later", severity=Severity.LOW)
        )
        assert "Arrived later" in [f.title for f in ctl.snapshot().findings], (
            "dashboard did not observe a finding written after launch — stale view"
        )
    finally:
        ctl.close()


@pytest.mark.asyncio
async def test_header_names_the_workspace_it_is_showing(config):
    """An operator must be able to read which workspace is on screen."""
    _seed(config, "alpha", ["Alpha finding"], ["http://alpha.test/a"])
    app = SpyderDashboard(config, workspace="alpha", profile="default")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        rendered = _screen_text(app)
    assert "alpha" in rendered, "dashboard never names its workspace on screen"


def _counts_row(screen: str, label: str) -> str:
    """The rendered '<label>   <n>' row — the panels report counts, not titles."""
    for line in screen.splitlines():
        if label in line:
            return line
    raise AssertionError(f"no {label!r} row on screen:\n{screen}")


@pytest.mark.asyncio
async def test_two_launch_cycles_leave_no_residue_on_screen(config):
    """Regression guard: cycle 2 on an empty workspace must not paint cycle 1's numbers."""
    _seed(config, "alpha", ["Distinctive Alpha Finding"], ["http://alpha.test/a"])
    _seed(config, "beta", [], [])

    first = SpyderDashboard(config, workspace="alpha", profile="default")
    async with first.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        alpha_screen = _screen_text(first)
    assert "alpha" in alpha_screen
    assert "1" in _counts_row(alpha_screen, "HIGH"), "seeded HIGH finding never reached the screen"

    second = SpyderDashboard(config, workspace="beta", profile="default")
    async with second.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        beta_screen = _screen_text(second)

    assert "beta" in beta_screen, "second launch does not name its own workspace"
    high_row = _counts_row(beta_screen, "HIGH")
    assert "1" not in high_row, f"empty workspace painted the previous cycle's count: {high_row!r}"
    assert "0" in _counts_row(beta_screen, "total")
