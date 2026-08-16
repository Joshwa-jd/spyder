"""Async-friendly event bus — the reactive backbone of SPYDER.

Subsystems (crawler, orchestrator, connectors, replay) publish lightweight
``Event`` records; consumers (the Textual dashboard, plugins, loggers) subscribe
to react. The bus is synchronous-publish / fan-out so it never blocks the async
recon pipeline, keeps a bounded history for late subscribers, and tracks
per-type counters for live HUD metrics.

This module deliberately holds *no* UI or network concerns — it is a pure,
testable pub/sub primitive shared across the architecture.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from ..utils.logging import get_logger

log = get_logger("events")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EventType(StrEnum):
    """Categories of events flowing through SPYDER."""

    # recon / crawl lifecycle
    RECON_START = "recon.start"
    RECON_DONE = "recon.done"
    CRAWL_PROGRESS = "crawl.progress"
    ENDPOINT_FOUND = "endpoint.found"
    PARAM_PROBED = "param.probed"
    FINGERPRINT = "fingerprint"

    # analysis / findings
    ANALYZER_DONE = "analyzer.done"
    FINDING = "finding"
    INTEL = "intel"
    JS_ROUTE = "js.route"
    SECRET = "secret"

    # orchestration
    CONNECTOR_START = "connector.start"
    CONNECTOR_DONE = "connector.done"
    REPLAY = "replay"
    PLUGIN = "plugin"

    # recon pipeline
    SUBDOMAIN = "subdomain"
    RECON_TOOL = "recon.tool"

    # generic
    STATUS = "status"
    LOG = "log"
    ERROR = "error"


@dataclass(frozen=True)
class Event:
    """An immutable record of something that happened in the platform."""

    type: EventType
    message: str = ""
    data: dict = field(default_factory=dict)
    source: str = "spyder"
    timestamp: datetime = field(default_factory=_utcnow)

    @property
    def clock(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")


Subscriber = Callable[[Event], None]


class EventBus:
    """Synchronous fan-out pub/sub with bounded history and counters.

    Publishing is non-blocking: each subscriber callback is invoked in turn and
    isolated so a misbehaving consumer cannot break the recon pipeline. The bus
    is loop-agnostic — callbacks run on whatever thread/loop calls ``publish``.
    """

    def __init__(self, history: int = 1000) -> None:
        self._subscribers: list[Subscriber] = []
        self._history: deque[Event] = deque(maxlen=history)
        self._counters: dict[EventType, int] = {}

    # --- subscription ---
    def subscribe(self, callback: Subscriber) -> Callable[[], None]:
        """Register a callback. Returns an unsubscribe function."""
        self._subscribers.append(callback)

        def unsubscribe() -> None:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

        return unsubscribe

    # --- publishing ---
    def publish(self, event: Event) -> Event:
        """Record and fan out an event to every subscriber."""
        self._history.append(event)
        self._counters[event.type] = self._counters.get(event.type, 0) + 1
        for callback in list(self._subscribers):
            try:
                callback(event)
            except Exception as exc:  # subscribers must never break the pipeline
                log.debug("event subscriber error: %s", exc)
        return event

    def emit(self, type: EventType, message: str = "", *, source: str = "spyder", **data) -> Event:
        """Convenience constructor + publish in one call."""
        return self.publish(Event(type=type, message=message, source=source, data=data))

    # --- introspection ---
    @property
    def history(self) -> list[Event]:
        return list(self._history)

    def recent(self, limit: int = 50) -> list[Event]:
        return list(self._history)[-limit:]

    def count(self, type: EventType) -> int:
        return self._counters.get(type, 0)

    @property
    def counters(self) -> dict[EventType, int]:
        return dict(self._counters)

    def clear(self) -> None:
        self._history.clear()
        self._counters.clear()
