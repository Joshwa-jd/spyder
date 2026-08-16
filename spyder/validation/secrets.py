"""Confidence-weighted secret validation with fake-secret suppression.

A regex match is only a *candidate*. This module decides how much an analyst
should trust it by combining the pattern's intrinsic strength with evidence from
the matched value itself: entropy, character diversity, length, and placeholder
detection. Structured high-specificity patterns (AWS keys, JWTs, Stripe live
keys) start trusted; greedy generic patterns must earn it.

The output is a :class:`SecretValidation` carrying a full :class:`Confidence`,
so every secret can explain *why* it is or is not believable — and obvious
placeholders are suppressed to NOISE instead of alarming the analyst.
"""
from __future__ import annotations

from dataclasses import dataclass

from .confidence import Confidence, ConfidenceLevel, VerificationState
from .entropy import charset_classes, is_placeholder, looks_random, shannon_entropy

# Intrinsic base score per pattern strength tier (how specific the regex is).
_BASE_BY_CONFIDENCE: dict[str, float] = {
    "high": 70.0,    # structured, low-false-positive patterns (AWS/JWT/Stripe…)
    "medium": 45.0,  # plausible but greedier (firebase, generic key=value)
    "low": 25.0,
}

# Patterns whose match *is* the proof — value-shape already verifies them, so we
# don't demand high entropy from short structured tokens.
_STRUCTURAL_KINDS: frozenset[str] = frozenset({
    "jwt", "aws_access_key_id", "aws_secret_access_key", "google_api_key",
    "slack_token", "slack_webhook", "stripe_key", "github_token",
    "twilio_api_key", "private_key",
})


@dataclass
class SecretValidation:
    """The validated verdict for one candidate secret."""

    kind: str
    confidence: Confidence

    @property
    def score(self) -> int:
        return self.confidence.score

    @property
    def level(self) -> ConfidenceLevel:
        return self.confidence.level

    @property
    def suppressed(self) -> bool:
        return self.confidence.suppressed

    @property
    def reasons(self) -> list[str]:
        return self.confidence.reasons


def validate_secret_value(
    kind: str,
    raw: str,
    base_confidence: str = "medium",
    *,
    context: str | None = None,
) -> SecretValidation:
    """Score a candidate secret match into a :class:`SecretValidation`.

    ``raw`` is the *unredacted* matched value (analysed here, never stored).
    ``base_confidence`` is the originating pattern's tier ("high"/"medium"/"low").
    ``context`` is an optional surrounding snippet for placeholder heuristics.
    """
    raw = (raw or "").strip()
    conf = Confidence(base=_BASE_BY_CONFIDENCE.get(base_confidence, 30.0))
    conf.add("pattern", 0.0, f"matched {base_confidence}-specificity {kind} pattern", source="regex")

    structural = kind in _STRUCTURAL_KINDS

    # --- placeholder / example suppression -------------------------------
    if is_placeholder(raw) or (context and is_placeholder(context)):
        conf.suppress("value resembles a placeholder/example, not a live secret", source="entropy")
        return SecretValidation(kind=kind, confidence=conf)

    # --- entropy & character diversity -----------------------------------
    entropy = shannon_entropy(raw)
    classes = charset_classes(raw)
    conf.add("entropy", 0.0, f"shannon entropy {entropy:.2f} bits/char", source="entropy")

    if structural:
        # Structural patterns are self-validating; entropy is a light bonus only.
        conf.add("structural", 10.0, f"{kind} has a self-verifying structure", source="pattern")
    else:
        # Generic patterns must look genuinely random to be trusted.
        if looks_random(raw):
            conf.add("randomness", 20.0, "value looks high-entropy / random", source="entropy")
        elif entropy < 2.5:
            conf.penalize("low_entropy", 25.0, "value entropy too low to be a real secret", source="entropy")
        elif classes < 2:
            conf.penalize("single_class", 12.0, "value uses a single character class", source="entropy")

    # --- length signal ---------------------------------------------------
    if len(raw) >= 32:
        conf.add("length", 8.0, f"{len(raw)} chars (long credential)", source="length")
    elif len(raw) < 12 and not structural:
        conf.penalize("short", 10.0, f"only {len(raw)} chars", source="length")

    # A generic value that ends up low after all signals is treated as noise.
    if not structural and conf.verification is VerificationState.UNVERIFIED and conf.score < 30:
        conf.suppress("aggregate confidence below noise floor", source="aggregate")

    return SecretValidation(kind=kind, confidence=conf)
