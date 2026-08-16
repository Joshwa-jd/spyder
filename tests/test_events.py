"""Tests for the async event bus and replay record foundation."""
from __future__ import annotations

from spyder.analysis.replay import ReplayHistory, record_replay
from spyder.core.events import Event, EventBus, EventType
from spyder.http.client import Transaction


def test_publish_and_subscribe():
    bus = EventBus()
    received: list[Event] = []
    bus.subscribe(received.append)
    bus.emit(EventType.RECON_START, "go")
    assert len(received) == 1
    assert received[0].type is EventType.RECON_START
    assert received[0].message == "go"


def test_unsubscribe_stops_delivery():
    bus = EventBus()
    received: list[Event] = []
    unsub = bus.subscribe(received.append)
    bus.emit(EventType.LOG, "one")
    unsub()
    bus.emit(EventType.LOG, "two")
    assert len(received) == 1


def test_history_and_counters():
    bus = EventBus(history=3)
    for i in range(5):
        bus.emit(EventType.ENDPOINT_FOUND, f"ep{i}")
    assert len(bus.history) == 3  # bounded
    assert bus.count(EventType.ENDPOINT_FOUND) == 5  # counter not bounded
    assert bus.recent(2)[-1].message == "ep4"


def test_subscriber_error_isolated():
    bus = EventBus()
    calls: list[int] = []

    def boom(_event):
        raise RuntimeError("subscriber blew up")

    bus.subscribe(boom)
    bus.subscribe(lambda _e: calls.append(1))
    bus.emit(EventType.STATUS, "still delivered")
    assert calls == [1]  # second subscriber unaffected


def _txn(body="", status=200, ms=10.0):
    return Transaction(
        id="t", method="GET", url="http://x/", request_headers={}, request_body=None,
        status=status, response_headers={}, body=body, elapsed_ms=ms,
    )


def test_replay_record_and_history():
    original = _txn("hello", 200, ms=10)
    replayed = _txn("hello world", 500, ms=40)
    rec = record_replay(0, original, replayed)
    assert rec.original_status == 200
    assert rec.replayed_status == 500
    assert rec.status_changed
    assert rec.timing_ms == 40.0

    hist = ReplayHistory()
    hist.add(rec)
    assert len(hist) == 1
    assert hist.search("http://x")  # url match
    assert not hist.search("nonexistent-host")
