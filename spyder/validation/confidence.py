"""The confidence primitive — explainable, deterministic scoring.

A ``Confidence`` is an accumulation of named ``Signal`` contributions. Each signal
nudges a 0–100 score and records *why*. A separate ``VerificationState`` captures
whether an external/active observation has confirmed, refuted, or suppressed the
result, which can override the score-derived level.

Design rules that keep analytics trustworthy:

  * **Deterministic** — no clocks, randomness, or set-ordering leaks into a score.
    Signals are combined in insertion order; rounding is half-up and explicit.
  * **Explainable** — every point is attributable to a named signal with a human
    detail string and an optional verification source.
  * **Bounded & monotonic** — scores clamp to [0, 100]; positive signals raise,
    negative signals lower, and the mapping to a level is a fixed threshold table.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum


def _round_half_up(value: float) -> int:
    """Deterministic rounding (banker's rounding makes scores ambiguous)."""
    if value >= 0:
        return int(math.floor(value + 0.5))
    return int(math.ceil(value - 0.5))


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


class ConfidenceLevel(StrEnum):
    """Analyst-facing reliability bands.

    ``CONFIRMED`` is reserved for results an active/observed signal verified (a
    live probe, an observed reflection); it is not reachable by score alone.
    ``NOISE`` marks results the engine suppressed as likely false positives.
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOISE = "noise"

    @property
    def rank(self) -> int:
        return {"noise": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}[self.value]

    @property
    def badge(self) -> str:
        """Short glyph + label for compact dashboard rendering."""
        return {
            "confirmed": "✔ confirmed",
            "high": "● high",
            "medium": "◐ medium",
            "low": "○ low",
            "noise": "⊘ noise",
        }[self.value]


class VerificationState(StrEnum):
    """Whether an external observation has spoken about a result."""

    UNVERIFIED = "unverified"   # only inferred from passive signals
    VERIFIED = "verified"       # an active/observed signal confirmed it
    REFUTED = "refuted"         # an active/observed signal contradicted it
    SUPPRESSED = "suppressed"   # deliberately filtered as noise / false positive


# Score → level thresholds (inclusive lower bounds). Fixed and deterministic.
_LEVEL_THRESHOLDS: tuple[tuple[float, ConfidenceLevel], ...] = (
    (80.0, ConfidenceLevel.HIGH),
    (55.0, ConfidenceLevel.MEDIUM),
    (30.0, ConfidenceLevel.LOW),
    (0.0, ConfidenceLevel.NOISE),
)


def level_for_score(score: float) -> ConfidenceLevel:
    """Map a numeric score to a level using the fixed threshold table."""
    for threshold, level in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return ConfidenceLevel.NOISE


@dataclass(frozen=True)
class Signal:
    """A single explainable contribution to a confidence score."""

    name: str
    weight: float
    detail: str = ""
    source: str = ""  # what produced/verified this signal (e.g. "status:200", "entropy")

    def describe(self) -> str:
        sign = "+" if self.weight >= 0 else ""
        body = self.detail or self.name
        return f"{body} ({sign}{self.weight:g})"


@dataclass
class Confidence:
    """An explainable, deterministic confidence assessment.

    Build it incrementally with :meth:`add` / :meth:`penalize`, then read
    :attr:`score`, :attr:`level`, :attr:`reasons`, and :attr:`sources`. The base
    is the starting score before signals are applied (default 0).
    """

    base: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    verification: VerificationState = VerificationState.UNVERIFIED

    # --- construction ---
    def add(self, name: str, weight: float, detail: str = "", source: str = "") -> Confidence:
        """Record a (positive or negative) signal contribution."""
        self.signals.append(Signal(name=name, weight=weight, detail=detail, source=source))
        return self

    def penalize(self, name: str, weight: float, detail: str = "", source: str = "") -> Confidence:
        """Record a negative contribution (``weight`` given as a positive magnitude)."""
        return self.add(name, -abs(weight), detail, source)

    def verify(self, source: str, detail: str = "verified by active signal") -> Confidence:
        """Promote to CONFIRMED via an external/observed verification."""
        self.verification = VerificationState.VERIFIED
        self.signals.append(Signal(name="verified", weight=0.0, detail=detail, source=source))
        return self

    def refute(self, source: str, detail: str = "contradicted by active signal") -> Confidence:
        self.verification = VerificationState.REFUTED
        self.signals.append(Signal(name="refuted", weight=0.0, detail=detail, source=source))
        return self

    def suppress(self, reason: str, source: str = "") -> Confidence:
        """Mark as noise/false-positive; level becomes NOISE regardless of score."""
        self.verification = VerificationState.SUPPRESSED
        self.signals.append(Signal(name="suppressed", weight=0.0, detail=reason, source=source))
        return self

    # --- derived values ---
    @property
    def raw(self) -> float:
        """Unrounded, unclamped score (base + signal weights)."""
        return self.base + sum(s.weight for s in self.signals)

    @property
    def score(self) -> int:
        """Deterministic 0–100 integer score."""
        if self.verification is VerificationState.SUPPRESSED:
            return 0
        if self.verification is VerificationState.REFUTED:
            return min(_round_half_up(_clamp(self.raw)), 20)
        return _round_half_up(_clamp(self.raw))

    @property
    def level(self) -> ConfidenceLevel:
        if self.verification is VerificationState.SUPPRESSED:
            return ConfidenceLevel.NOISE
        if self.verification is VerificationState.VERIFIED:
            return ConfidenceLevel.CONFIRMED
        if self.verification is VerificationState.REFUTED:
            return ConfidenceLevel.NOISE
        return level_for_score(self.score)

    @property
    def suppressed(self) -> bool:
        return self.verification is VerificationState.SUPPRESSED

    @property
    def trustworthy(self) -> bool:
        """Whether an analyst should treat this as a real, actionable signal."""
        return self.level.rank >= ConfidenceLevel.MEDIUM.rank

    @property
    def reasons(self) -> list[str]:
        """Human-readable reason trace, in the order signals were applied."""
        return [s.describe() for s in self.signals if s.detail or s.weight]

    @property
    def sources(self) -> list[str]:
        """Distinct verification/evidence sources, sorted for stable output."""
        return sorted({s.source for s in self.signals if s.source})

    def explain(self) -> dict:
        """Structured, serializable explanation for reports/dashboard."""
        return {
            "base": self.base,
            "score": self.score,
            "level": self.level.value,
            "verification": self.verification.value,
            "reasons": self.reasons,
            "sources": self.sources,
            "signals": [
                {"name": s.name, "weight": s.weight, "detail": s.detail, "source": s.source}
                for s in self.signals
            ],
        }

    # to_dict is an alias kept for symmetry with the rest of the codebase.
    to_dict = explain

    @classmethod
    def from_dict(cls, d: dict) -> Confidence:
        conf = cls(base=float(d.get("base", 0.0)))
        for s in d.get("signals", []):
            conf.signals.append(
                Signal(
                    name=s.get("name", ""),
                    weight=float(s.get("weight", 0.0)),
                    detail=s.get("detail", ""),
                    source=s.get("source", ""),
                )
            )
        try:
            conf.verification = VerificationState(d.get("verification", "unverified"))
        except ValueError:
            conf.verification = VerificationState.UNVERIFIED
        return conf


def blend(*confidences: Confidence, base: float = 0.0) -> Confidence:
    """Combine several confidences into one multi-signal assessment.

    Each input's signals are folded into the result (preserving their reason
    trace), and the strongest verification state wins. This is how SPYDER turns
    multiple independent observations of the same thing into a single, more
    trustworthy score — the essence of multi-signal validation.
    """
    out = Confidence(base=base)
    strongest = VerificationState.UNVERIFIED
    order = {
        VerificationState.SUPPRESSED: 3,
        VerificationState.VERIFIED: 2,
        VerificationState.REFUTED: 1,
        VerificationState.UNVERIFIED: 0,
    }
    for conf in confidences:
        out.base += conf.base
        out.signals.extend(conf.signals)
        if order[conf.verification] > order[strongest]:
            strongest = conf.verification
    out.verification = strongest
    return out
