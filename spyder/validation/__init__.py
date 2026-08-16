"""SPYDER validation — the recon intelligence accuracy & confidence engine.

This package is the *trust layer* of SPYDER. Where the analysis modules discover
raw attack-surface intelligence, the validation layer asks a harder question for
every result: *how much should an analyst believe it?*

It does this deterministically and explainably. Every validated result carries a
``Confidence`` object built from named ``Signal`` contributions, so the dashboard
and reports can always answer:

  * why was this detected?
  * what signals caused it?
  * how reliable is it?
  * what evidence supports it?

Nothing here performs I/O, randomness, or time-dependent logic — given the same
inputs it produces byte-identical scores, which is what makes the analytics
trustworthy and the tests meaningful.
"""
from __future__ import annotations

from .confidence import (
    Confidence,
    ConfidenceLevel,
    Signal,
    VerificationState,
    blend,
    level_for_score,
)
from .endpoints import (
    ValidatedEndpoint,
    deduplicate_endpoints,
    validate_endpoint,
    validate_intel,
)
from .entropy import (
    charset_classes,
    is_placeholder,
    looks_random,
    shannon_entropy,
)
from .fingerprint import TechConfidence, validate_technologies
from .normalize import dedup_key, normalize_url, route_template
from .replay import (
    REPLAY_NOISE_HEADERS,
    ReplayConfidence,
    filter_header_noise,
    meaningful_body_change,
    normalize_diff_lines,
    normalize_diff_text,
    replay_confidence,
)
from .secrets import SecretValidation, validate_secret_value
from .summary import SignalQuality, signal_quality

__all__ = [
    # confidence core
    "Confidence",
    "ConfidenceLevel",
    "Signal",
    "VerificationState",
    "blend",
    "level_for_score",
    # entropy
    "shannon_entropy",
    "is_placeholder",
    "looks_random",
    "charset_classes",
    # normalization
    "normalize_url",
    "route_template",
    "dedup_key",
    # secrets
    "SecretValidation",
    "validate_secret_value",
    # endpoints
    "ValidatedEndpoint",
    "validate_endpoint",
    "validate_intel",
    "deduplicate_endpoints",
    # fingerprint
    "TechConfidence",
    "validate_technologies",
    # replay
    "ReplayConfidence",
    "replay_confidence",
    "filter_header_noise",
    "REPLAY_NOISE_HEADERS",
    "normalize_diff_text",
    "normalize_diff_lines",
    "meaningful_body_change",
    # summary
    "SignalQuality",
    "signal_quality",
]
