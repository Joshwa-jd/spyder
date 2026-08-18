"""Technology fingerprint scoring.

Passive evidence differs wildly in strength: a ``Server: nginx/1.25`` header is
an explicit server-volunteered fact, while a cookie *named* ``PHPSESSID`` is a
convention anyone can imitate. This module turns the evidence attached to a
:class:`~spyder.analysis.fingerprint.Technology` into an explainable confidence.

Two rules define the model:

  * **A single passive signal never reaches CONFIRMED.** Every passive signal —
    including a Server header — is attacker-controlled: an origin can send any
    header it likes. Passive evidence therefore tops out at HIGH. Treating a
    spoofable string as confirmed fact is what makes a scanner's output
    untrustworthy.
  * **Confidence rises only when *independent* evidence agrees.** Corroboration
    is counted per evidence *source*, not per observation: two headers are one
    header-shaped opinion, whereas a header plus a cookie plus a meta generator
    are three things that would all have to be wrong together.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis.fingerprint import Evidence, EvidenceSource, Technology
from .confidence import Confidence, ConfidenceLevel

#: Bonus per corroborating evidence source beyond the first, and its cap.
_CORROBORATION_STEP = 10.0
_CORROBORATION_CAP = 20.0

#: Independent sources required before passive evidence may be called CONFIRMED.
_CONFIRM_MIN_SOURCES = 2
#: Score required alongside that, so weak-but-plentiful evidence stays HIGH.
_CONFIRM_MIN_SCORE = 80.0

#: Bonus for the same technology recurring across separate responses, and cap.
_REPEAT_STEP = 3.0
_REPEAT_CAP = 10.0


@dataclass
class TechConfidence:
    """A fingerprinted technology with its confidence assessment."""

    name: str
    category: str = ""
    version: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    confidence: Confidence = field(default_factory=Confidence)

    @property
    def level(self) -> ConfidenceLevel:
        return self.confidence.level

    @property
    def score(self) -> int:
        return self.confidence.score

    @property
    def verified(self) -> bool:
        return self.level is ConfidenceLevel.CONFIRMED

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name

    @property
    def sources(self) -> tuple[EvidenceSource, ...]:
        seen: list[EvidenceSource] = []
        for e in self.evidence:
            if e.source not in seen:
                seen.append(e.source)
        return tuple(sorted(seen))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "score": self.score,
            "level": self.level.value,
            "sources": [s.value for s in self.sources],
            "evidence": [e.to_dict() for e in self.evidence],
            "confidence": self.confidence.explain(),
        }


def score_technology(tech: Technology, *, seen_in: int = 1) -> TechConfidence:
    """Score one technology from the evidence attached to it.

    The strongest single observation sets the floor; each *additional
    independent source* adds a bounded bonus. ``seen_in`` is how many separate
    responses reported this technology — repetition of the same passive signal
    is worth a little, but never enough to manufacture a confirmation.
    """
    conf = Confidence(base=0.0)
    if not tech.evidence:
        # Nothing observed: refuse to claim anything. Unknown beats a guess.
        conf.suppress("no evidence recorded for this technology", source="fingerprint")
        return TechConfidence(
            name=tech.name, category=tech.category, version=tech.version, confidence=conf
        )

    strongest = max(tech.evidence, key=lambda e: (e.weight, e.kind))
    conf.base = strongest.weight
    conf.add(
        "primary-evidence", 0.0,
        f"{strongest.detail} [{strongest.source.value}]",
        source=f"{strongest.source.value}:{strongest.kind}",
    )

    # Corroboration counts distinct sources, so repeating one signal adds nothing.
    corroborating = [s for s in tech.sources if s is not strongest.source]
    for extra in corroborating:
        support = max(
            (e for e in tech.evidence if e.source is extra),
            key=lambda e: (e.weight, e.kind),
        )
        conf.add(
            "corroboration",
            min(_CORROBORATION_STEP, _CORROBORATION_CAP),
            f"independently attested by {support.detail} [{extra.value}]",
            source=f"{extra.value}:{support.kind}",
        )
    # Enforce the cap across all corroboration signals.
    total_bonus = sum(s.weight for s in conf.signals if s.name == "corroboration")
    if total_bonus > _CORROBORATION_CAP:
        conf.penalize(
            "corroboration-cap", total_bonus - _CORROBORATION_CAP,
            f"corroboration bonus capped at +{_CORROBORATION_CAP:g}", source="policy",
        )

    if seen_in > 1:
        conf.add(
            "repetition", min(_REPEAT_CAP, _REPEAT_STEP * (seen_in - 1)),
            f"reported across {seen_in} responses", source="multi-response",
        )

    # CONFIRMED requires genuinely independent agreement, never a lone header.
    independent = len(tech.sources)
    if independent >= _CONFIRM_MIN_SOURCES and conf.score >= _CONFIRM_MIN_SCORE:
        conf.verify(
            source="corroboration:" + "+".join(s.value for s in tech.sources),
            detail=f"{independent} independent evidence sources agree",
        )

    return TechConfidence(
        name=tech.name,
        category=tech.category,
        version=tech.version,
        evidence=list(tech.evidence),
        confidence=conf,
    )


def validate_technologies(
    technologies: list[Technology],
    *,
    corroborations: dict[str, int] | None = None,
) -> list[TechConfidence]:
    """Score fingerprinted technologies, most trustworthy first.

    ``corroborations`` optionally maps a technology name to how many independent
    responses reported it. Output is sorted by score (desc) then name, so the
    result is a deterministic function of the input.
    """
    corroborations = corroborations or {}
    out = [
        score_technology(tech, seen_in=corroborations.get(tech.name, 1))
        for tech in technologies
    ]
    out.sort(key=lambda t: (-t.score, t.name))
    return out
