"""Passive response analysis: diffing, similarity, reflection, timing baselines.

This module is deliberately analytical. It compares responses and surfaces
observations for a human analyst; it never decides to attack anything.
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from ..http.client import Transaction

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def normalize(body: str) -> str:
    """Strip tags and collapse whitespace for structural comparison."""
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", body)).strip()


def similarity(a: str, b: str) -> float:
    """Ratio in [0,1]; 1.0 means identical normalized content."""
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, normalize(a), normalize(b)).ratio()


@dataclass
class ResponseDiff:
    similarity: float
    status_changed: bool
    length_delta: int
    timing_delta_ms: float
    new_headers: list[str] = field(default_factory=list)
    removed_headers: list[str] = field(default_factory=list)
    notable: list[str] = field(default_factory=list)


def diff(base: Transaction, other: Transaction) -> ResponseDiff:
    sim = similarity(base.body, other.body)
    base_h = set(base.response_headers)
    other_h = set(other.response_headers)
    d = ResponseDiff(
        similarity=round(sim, 4),
        status_changed=base.status != other.status,
        length_delta=len(other.body) - len(base.body),
        timing_delta_ms=round(other.elapsed_ms - base.elapsed_ms, 2),
        new_headers=sorted(other_h - base_h),
        removed_headers=sorted(base_h - other_h),
    )
    if d.status_changed:
        d.notable.append(f"status {base.status} -> {other.status}")
    if sim < 0.95:
        d.notable.append(f"content similarity {sim:.2f}")
    if abs(d.length_delta) > 100:
        d.notable.append(f"length delta {d.length_delta:+d}")
    if d.timing_delta_ms > 1000:
        d.notable.append(f"timing delta {d.timing_delta_ms:+.0f}ms")
    return d


class TimingBaseline:
    """Tracks response timings to flag statistical anomalies for manual review."""

    def __init__(self) -> None:
        self._samples: list[float] = []

    def add(self, ms: float) -> None:
        self._samples.append(ms)

    def is_anomaly(self, ms: float, z: float = 3.0) -> bool:
        if len(self._samples) < 5:
            return False
        mean = statistics.mean(self._samples)
        stdev = statistics.pstdev(self._samples) or 1.0
        return (ms - mean) / stdev > z

    @property
    def mean_ms(self) -> float:
        return round(statistics.mean(self._samples), 2) if self._samples else 0.0


def find_reflections(value: str, body: str) -> bool:
    """Report whether a marker value appears reflected in a response body."""
    return bool(value) and value in body
