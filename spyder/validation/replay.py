"""Replay analysis accuracy — confidence, anomaly detection, header de-noising.

Replays are only useful if an analyst can trust that a *difference* between the
original and replayed response is real signal rather than server noise. Two
mechanisms here make that trustworthy:

  * **Header de-noising** — volatile headers (Date, request ids, ephemeral
    cookies, timing) are filtered before they count as a "change".
  * **Replay confidence** — a deterministic score for how stable/equivalent the
    replay is, plus anomaly flags for status flips, content divergence, and
    reflections (an actively-observed signal that *verifies* reflection).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .confidence import Confidence, ConfidenceLevel

# Headers that routinely differ between two otherwise-identical responses and so
# must not be treated as meaningful changes during replay diffing.
REPLAY_NOISE_HEADERS: frozenset[str] = frozenset({
    "date", "age", "expires", "last-modified", "etag",
    "set-cookie", "x-request-id", "x-correlation-id", "x-trace-id",
    "x-amzn-requestid", "x-amzn-trace-id", "cf-ray", "x-served-by",
    "x-cache", "x-cache-hits", "x-timer", "x-runtime", "x-response-time",
    "report-to", "nel", "alt-svc", "via", "keep-alive", "connection",
    "content-security-policy-report-only",
})


def filter_header_noise(items):
    """Drop volatile headers from a diff iterable of ``(name, ...)`` tuples.

    Works uniformly on ``added``/``removed``/``changed`` lists where the first
    tuple element is the (case-insensitive) header name. Returns a new list.
    """
    out = []
    for item in items:
        name = (item[0] if isinstance(item, (tuple, list)) else item)
        if str(name).lower() not in REPLAY_NOISE_HEADERS:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Deterministic diff normalization
# ---------------------------------------------------------------------------
#
# A replay diff is only trustworthy if the lines it highlights are *meaningful*
# changes rather than per-request volatility (a clock tick, a fresh CSRF token, a
# rotated request id echoed into the body). We mask those volatile spans with
# stable placeholders before diffing, so two responses that differ only in noise
# normalize to identical text. The masking is purely lexical and ordered, so the
# same input always yields the same output — no clocks, randomness, or locale.

# (pattern, placeholder) applied in order. Earlier, more specific patterns win so
# a full ISO timestamp is masked before its date/time components are considered.
_DIFF_NOISE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # ISO-8601 timestamp (with optional fractional seconds / timezone)
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    # RFC-1123 HTTP date, e.g. "Wed, 21 Oct 2015 07:28:00 GMT"
    (re.compile(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT"), "<TS>"),
    # UUID
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
    # bare date / time
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "<DATE>"),
    (re.compile(r"\d{2}:\d{2}:\d{2}"), "<TIME>"),
    # long hex digest (md5/sha/etag-ish)
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    # epoch seconds / millis
    (re.compile(r"\b\d{10,13}\b"), "<EPOCH>"),
    # long opaque token (base64url / nonce / csrf value)
    (re.compile(r"\b[A-Za-z0-9_\-]{24,}\b"), "<TOKEN>"),
)


def normalize_diff_text(text: str) -> str:
    """Mask volatile spans (timestamps, ids, nonces) with stable placeholders.

    Deterministic and idempotent: identical input always yields identical output,
    so a diff over normalized text reflects only meaningful changes.
    """
    if not text:
        return ""
    for pattern, placeholder in _DIFF_NOISE_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def normalize_diff_lines(text: str) -> list[str]:
    """Split into lines after volatile-span masking (for line-aligned diffing)."""
    return normalize_diff_text(text).splitlines()


def meaningful_body_change(a: str, b: str) -> bool:
    """True only if two bodies differ after volatile spans are normalized away."""
    return normalize_diff_text(a or "") != normalize_diff_text(b or "")


@dataclass
class ReplayConfidence:
    """How trustworthy/stable a replay comparison is, plus anomaly flags."""

    confidence: Confidence
    anomalies: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return self.confidence.score

    @property
    def level(self) -> ConfidenceLevel:
        return self.confidence.level

    @property
    def stable(self) -> bool:
        """Replay reproduced an equivalent response (diffs are trustworthy)."""
        return not self.anomalies and self.confidence.trustworthy

    @property
    def anomalous(self) -> bool:
        return bool(self.anomalies)

    @property
    def reasons(self) -> list[str]:
        """Ordered, human-readable trace of *why* this replay scored as it did."""
        return self.confidence.reasons

    @property
    def sources(self) -> list[str]:
        """Distinct evidence sources backing the score (for traceability)."""
        return self.confidence.sources


def replay_confidence(
    *,
    similarity: float,
    original_status: int | None,
    replayed_status: int | None,
    length_delta: int = 0,
    reflected: list[str] | None = None,
    meaningful_header_changes: int = 0,
) -> ReplayConfidence:
    """Score the stability/equivalence of a replay and flag anomalies.

    A high score means original and replay represent the same underlying state,
    so any reported diff is real signal. Reflections are treated as an actively
    observed fact and *verify* the reflection regardless of the stability score.
    """
    reflected = reflected or []
    anomalies: list[str] = []
    # Start from structural similarity — the dominant stability signal.
    conf = Confidence(base=round(max(0.0, min(1.0, similarity)) * 100.0, 2))
    conf.add("similarity", 0.0, f"normalized content similarity {similarity:.2f}", source="diff")

    status_changed = original_status != replayed_status
    if status_changed:
        conf.penalize("status_flip", 35.0,
                      f"status changed {original_status}→{replayed_status}", source="http")
        anomalies.append(f"status {original_status}→{replayed_status}")
    else:
        conf.add("status_stable", 5.0, f"status held at {replayed_status}", source="http")

    if abs(length_delta) > 512:
        conf.penalize("length_divergence", 15.0,
                      f"body length changed by {length_delta:+d}", source="diff")
        anomalies.append(f"length {length_delta:+d}")
    elif similarity < 0.85:
        anomalies.append(f"similarity {similarity:.2f}")

    if meaningful_header_changes:
        conf.penalize("header_changes", min(15.0, 4.0 * meaningful_header_changes),
                      f"{meaningful_header_changes} non-noise header change(s)", source="headers")

    if reflected:
        # Observing our submitted values echoed back is a confirmed fact.
        conf.verify("reflection",
                    f"{len(reflected)} submitted value(s) reflected in response")
        anomalies.append(f"reflection×{len(reflected)}")

    return ReplayConfidence(confidence=conf, anomalies=anomalies)
