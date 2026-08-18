"""Aggregate signal-quality metrics for the dashboard's reliability widgets.

Rolls the per-result confidence assessments up into a single, trustworthy view
of *how good the intelligence is right now*: how many endpoints are verified vs
merely inferred, how many secrets survived fake-suppression, the replay stability
rate, and a single 0–100 reliability index an analyst can glance at.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .confidence import ConfidenceLevel

if TYPE_CHECKING:
    from ..analysis.replay import ReplayAnalytics
    from .endpoints import ValidatedEndpoint

_LEVEL_ORDER = ("confirmed", "high", "medium", "low", "noise")


def _empty_levels() -> dict[str, int]:
    return {lvl: 0 for lvl in _LEVEL_ORDER}


@dataclass
class SignalQuality:
    """Platform-wide intelligence reliability metrics."""

    endpoints_total: int = 0
    endpoints_verified: int = 0
    endpoints_trustworthy: int = 0
    endpoint_levels: dict[str, int] = field(default_factory=_empty_levels)
    duplicates_suppressed: int = 0

    secrets_total: int = 0
    secrets_suppressed: int = 0
    secrets_verified: int = 0
    secret_levels: dict[str, int] = field(default_factory=dict)

    replays_total: int = 0
    replays_stable: int = 0
    replays_anomalous: int = 0
    replay_avg_confidence: float = 0.0

    tech_total: int = 0
    tech_verified: int = 0

    @property
    def verified_ratio(self) -> float:
        return self.endpoints_verified / self.endpoints_total if self.endpoints_total else 0.0

    @property
    def replay_stability(self) -> float:
        return self.replays_stable / self.replays_total if self.replays_total else 0.0

    @property
    def reliability_index(self) -> int:
        """A single 0–100 trust score blending the strongest available signals.

        Each contributing dimension is averaged only over the dimensions that
        actually have data, so an empty workspace reads 0 rather than a
        misleadingly-high default.
        """
        parts: list[float] = []
        if self.endpoints_total:
            parts.append(100.0 * self.endpoints_trustworthy / self.endpoints_total)
        if self.replays_total:
            parts.append(self.replay_avg_confidence)
        if self.secrets_total:
            parts.append(100.0 * self.secrets_verified / self.secrets_total)
        if self.tech_total:
            parts.append(100.0 * self.tech_verified / self.tech_total)
        if not parts:
            return 0
        return int(round(sum(parts) / len(parts)))

    @property
    def grade(self) -> str:
        idx = self.reliability_index
        if idx >= 85:
            return "A"
        if idx >= 70:
            return "B"
        if idx >= 50:
            return "C"
        if idx >= 30:
            return "D"
        return "F"


def signal_quality(
    endpoints: list[ValidatedEndpoint] | None = None,
    *,
    secret_levels: dict[str, int] | None = None,
    duplicates_suppressed: int = 0,
    replay_analytics: ReplayAnalytics | None = None,
    tech_verified: int = 0,
    tech_total: int = 0,
) -> SignalQuality:
    """Compute the platform-wide :class:`SignalQuality` snapshot."""
    sq = SignalQuality(duplicates_suppressed=duplicates_suppressed)

    endpoints = endpoints or []
    sq.endpoints_total = len(endpoints)
    levels = _empty_levels()
    for ve in endpoints:
        lvl = ve.level.value
        levels[lvl] = levels.get(lvl, 0) + 1
        if ve.level is ConfidenceLevel.CONFIRMED:
            sq.endpoints_verified += 1
        if ve.trustworthy:
            sq.endpoints_trustworthy += 1
    sq.endpoint_levels = levels

    if secret_levels:
        sq.secret_levels = dict(secret_levels)
        sq.secrets_total = sum(secret_levels.values())
        sq.secrets_verified = secret_levels.get("confirmed", 0) + secret_levels.get("high", 0)

    if replay_analytics is not None and not replay_analytics.empty:
        sq.replays_total = replay_analytics.total
        sq.replays_stable = replay_analytics.stable
        sq.replays_anomalous = replay_analytics.anomalous
        sq.replay_avg_confidence = replay_analytics.avg_confidence

    sq.tech_total = tech_total
    sq.tech_verified = tech_verified
    return sq
