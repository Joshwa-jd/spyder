"""Tests for the replay workbench: deterministic diff normalization, evidence
traceability, timeline/anomaly analytics, confidence badges, and the render
functions that visualize all of it.

As with the rest of the validation layer, the load-bearing property is
*determinism* — identical inputs must yield byte-identical normalization, scores,
and orderings so the workbench and dashboard numbers can be trusted.
"""
from __future__ import annotations

import pytest

from spyder.analysis.replay import (
    ReplayHistory,
    record_replay,
)
from spyder.core.config import SpyderConfig
from spyder.http.client import Transaction
from spyder.ui import theme
from spyder.ui.dashboard import (
    DashboardState,
    SpyderDashboard,
    render_replay_activity,
    render_replay_trust,
)
from spyder.ui.workbench import (
    ReplayWorkbenchScreen,
    render_body_diff,
    render_compare,
    render_replay_timeline,
    render_wb_analytics,
)
from spyder.validation import (
    meaningful_body_change,
    normalize_diff_lines,
    normalize_diff_text,
)


def _txn(body="", status=200, ms=10.0, *, url="http://x/", method="GET",
         request_body=None, response_headers=None):
    return Transaction(
        id="t", method=method, url=url, request_headers={}, request_body=request_body,
        status=status, response_headers=response_headers or {}, body=body, elapsed_ms=ms,
    )


# ---------------------------------------------------------------------------
# Deterministic diff normalization
# ---------------------------------------------------------------------------


def test_normalize_masks_volatile_spans():
    text = (
        "ts=2026-06-07T12:30:00Z id=550e8400-e29b-41d4-a716-446655440000 "
        "etag=9f8c1d2e3a4b5c6d7e8f0a1b epoch=1717761000 "
        "csrf=abcdEFGH1234ijklMNOP5678qrst"
    )
    out = normalize_diff_text(text)
    assert "2026-06-07T12:30:00Z" not in out
    assert "550e8400" not in out
    assert "9f8c1d2e3a4b5c6d7e8f0a1b" not in out
    assert "1717761000" not in out
    assert "abcdEFGH1234ijklMNOP5678qrst" not in out
    assert "<TS>" in out and "<UUID>" in out and "<HEX>" in out


def test_normalize_is_deterministic_and_idempotent():
    text = "issued 2026-06-07 at 12:30:00 token=AAAABBBBCCCCDDDDEEEEFFFF"
    once = normalize_diff_text(text)
    assert once == normalize_diff_text(text)        # deterministic
    assert once == normalize_diff_text(once)        # idempotent


def test_normalize_preserves_real_content():
    text = '{"role": "admin", "items": 3}'
    assert normalize_diff_text(text) == text


def test_normalize_empty():
    assert normalize_diff_text("") == ""
    assert normalize_diff_lines("") == []


def test_meaningful_body_change_ignores_noise_only_diffs():
    a = "session started 2026-06-07T10:00:00Z user=admin"
    b = "session started 2026-06-07T11:45:12Z user=admin"
    assert not meaningful_body_change(a, b)         # only the timestamp differs
    c = "session started 2026-06-07T10:00:00Z user=root"
    assert meaningful_body_change(a, c)             # a real value changed


# ---------------------------------------------------------------------------
# Evidence traceability on records
# ---------------------------------------------------------------------------


def test_record_carries_evidence_trace():
    rec = record_replay(0, _txn("hello", 200, ms=10), _txn("hello", 200, ms=12))
    assert rec.confidence_reasons          # non-empty reason trace
    assert any("similarity" in r for r in rec.confidence_reasons)
    assert rec.evidence                    # distinct evidence sources


def test_record_roundtrip_preserves_new_fields():
    rec = record_replay(
        0,
        _txn("base", 200, url="http://x/a?q=marker1234"),
        _txn("base marker1234 echoed", 200, url="http://x/a?q=marker1234"),
    )
    from spyder.analysis.replay import ReplayRecord
    restored = ReplayRecord.from_dict(rec.to_dict())
    assert restored.confidence_reasons == rec.confidence_reasons
    assert restored.evidence == rec.evidence
    assert restored.confidence_score == rec.confidence_score


# ---------------------------------------------------------------------------
# Record visual helpers
# ---------------------------------------------------------------------------


def test_record_marker_and_status_flow():
    anomalous = record_replay(0, _txn("a" * 50, 200), _txn("b" * 4000, 500))
    assert anomalous.marker == "⚠"
    assert anomalous.status_flow == "200→500"
    stable = record_replay(0, _txn("same", 200, ms=10), _txn("same", 200, ms=11))
    assert stable.marker in ("●", "○")
    assert stable.status_flow == "200→200"


# ---------------------------------------------------------------------------
# Timeline + anomaly analytics
# ---------------------------------------------------------------------------


def _history_with(n_stable=2, n_anom=1):
    h = ReplayHistory()
    for _ in range(n_stable):
        h.add(record_replay(0, _txn("ok", 200, ms=10), _txn("ok", 200, ms=11)))
    for _ in range(n_anom):
        h.add(record_replay(0, _txn("x" * 50, 200), _txn("y" * 5000, 500)))
    return h


def test_timeline_is_deterministic_and_ordered():
    h = _history_with()
    tl1 = [r.id for r in h.timeline()]
    tl2 = [r.id for r in h.timeline()]
    assert tl1 == tl2                       # deterministic
    assert tl1 == sorted(tl1)               # chronological by id
    assert h.timeline(limit=2) == sorted(h.records, key=lambda r: r.id)[-2:]


def test_analytics_stability_and_anomaly_counts():
    a = _history_with(n_stable=2, n_anom=1).analytics()
    assert a.total == 3
    assert a.stable == 2
    assert a.anomalous == 1
    assert 60.0 <= a.stability_pct <= 70.0   # 2/3
    assert a.anomaly_counts.get("status") == 1
    assert len(a.confidence_series) == 3


def test_anomaly_breakdown_sorted():
    bd = _history_with().anomaly_breakdown()
    assert "status" in bd
    assert list(bd.keys()) == sorted(bd.keys())


# ---------------------------------------------------------------------------
# Confidence badges
# ---------------------------------------------------------------------------


def test_confidence_badge_deterministic_and_colored():
    b1 = theme.confidence_badge("high", 82)
    assert b1 == theme.confidence_badge("high", 82)
    assert theme.SUCCESS in b1 and "high" in b1 and "82" in b1
    plain = theme.confidence_badge("noise", markup=False)
    assert plain == "⊘ noise"


# ---------------------------------------------------------------------------
# Render functions
# ---------------------------------------------------------------------------


def test_render_compare_and_body_diff():
    rec = record_replay(
        0,
        _txn("served 2026-06-07T10:00:00Z", 200, url="http://x/a?q=marker1234"),
        _txn("served 2026-06-07T11:11:11Z marker1234", 200, url="http://x/a?q=marker1234"),
    )
    assert render_compare(rec) is not None
    # The bodies differ only by a timestamp + the reflected marker; with the
    # reflected token present the diff is meaningful, so it renders rows.
    assert render_body_diff(rec, normalize=True) is not None


def test_render_body_diff_collapses_noise_only_change():
    rec = record_replay(
        0,
        _txn("clock 2026-06-07T10:00:00Z", 200),
        _txn("clock 2026-06-07T22:22:22Z", 200),
    )
    normalized = render_body_diff(rec, normalize=True)
    assert "identical" in normalized.plain
    raw = render_body_diff(rec, normalize=False)
    assert "identical" not in raw.plain      # raw view still shows the change


def test_render_timeline_and_dashboard_widgets():
    h = _history_with()
    records = h.records
    assert render_replay_timeline(records) is not None
    assert render_replay_timeline([]) is not None       # empty-safe

    state = DashboardState(replay=records, replay_analytics=h.analytics())
    assert render_replay_activity(state) is not None
    trust = render_replay_trust(state)
    assert trust.row_count >= 3
    # Empty state must not crash.
    assert render_replay_trust(DashboardState()) is not None
    assert render_wb_analytics(h.analytics(), records[0]) is not None


# ---------------------------------------------------------------------------
# Live integration — dashboard panels + workbench screen mount
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_config(tmp_path):
    cfg = SpyderConfig(home=tmp_path, profile_name="test")
    cfg.ensure_dirs()
    return cfg


async def test_workbench_screen_mounts_from_dashboard(isolated_config):
    app = SpyderDashboard(isolated_config, workspace="test", profile="test")
    async with app.run_test() as pilot:
        # New dashboard replay panels compose without error.
        assert app.query_one("#replay-activity")
        assert app.query_one("#replay-trust")
        # Seed a replay so the workbench has content, then open it (ctrl+w path).
        app.controller.orch.replay_history.add(
            record_replay(0, _txn("ok", 200), _txn("ok", 200))
        )
        app.action_workbench()
        await pilot.pause()
        assert isinstance(app.screen, ReplayWorkbenchScreen)
        # Selecting/normalizing the detail view must not crash.
        app.screen.action_toggle_normalize()
        await pilot.pause()
