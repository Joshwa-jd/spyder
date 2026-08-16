"""Smoke tests for the Textual dashboard — mounts headless via the test pilot."""
from __future__ import annotations

import pytest

from spyder.core.config import SpyderConfig
from spyder.ui.dashboard import (
    DashboardState,
    SpyderDashboard,
    render_attack_surface,
    render_high_interest,
    render_recon_summary,
    render_signal_quality,
)
from spyder.validation.summary import SignalQuality


@pytest.fixture
def isolated_config(tmp_path):
    cfg = SpyderConfig(home=tmp_path, profile_name="test")
    cfg.ensure_dirs()
    return cfg


def test_render_helpers_handle_empty_state():
    # Renderers must not crash on a fresh (empty) workspace.
    state = DashboardState()
    assert render_recon_summary(state) is not None
    assert render_attack_surface(state) is not None
    assert render_high_interest(state) is not None
    assert render_signal_quality(state) is not None


def test_render_signal_quality_with_data():
    state = DashboardState(quality=SignalQuality(
        endpoints_total=5, endpoints_verified=3, endpoints_trustworthy=4,
        secrets_total=2, secrets_verified=1, duplicates_suppressed=4,
    ))
    table = render_signal_quality(state)
    assert table is not None
    assert table.row_count >= 3  # reliability + endpoint rows rendered


async def test_dashboard_mounts(isolated_config):
    app = SpyderDashboard(isolated_config, workspace="test", profile="test")
    async with app.run_test() as pilot:
        # Core widgets are present and composed.
        assert app.query_one("#topbar")
        assert app.query_one("#event-stream")
        assert app.query_one("#recon-summary")
        assert app.query_one("#high-interest")
        assert app.query_one("#command-output")
        assert app.query_one("#cmd-input")
        # Controller is wired to the workspace and produces a snapshot.
        assert app.controller.workspace == "test"
        assert app.controller.snapshot() is not None
        await pilot.pause()


async def test_dashboard_help_command(isolated_config):
    app = SpyderDashboard(isolated_config, workspace="test", profile="test")
    async with app.run_test() as pilot:
        await app._dispatch("help")
        await app._dispatch("refresh")
        await pilot.pause()
        # Should not have crashed; controller still usable.
        assert app.controller.snapshot() is not None


async def test_repeated_dashboard_launches_are_clean(isolated_config):
    """Mounting and tearing down the dashboard repeatedly must not corrupt state.

    Regression guard for the "repeated dashboard launches" concern: each launch
    composes a fresh app, mounts its widgets, produces a snapshot, and unmounts
    cleanly on context exit. A leaked terminal mode or a widget-id collision from
    a prior launch would surface here as an exception on the second/third pass.
    """
    for _ in range(3):
        app = SpyderDashboard(isolated_config, workspace="test", profile="test")
        async with app.run_test() as pilot:
            assert app.query_one("#event-stream")
            assert app.query_one("#cmd-input")
            assert app.controller.snapshot() is not None
            await pilot.pause()
