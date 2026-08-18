"""Attack-surface quality: endpoint de-duplication, confidence & importance.

Two complementary scores per endpoint:

  * **importance** — *how much an analyst should care* (auth/admin/api class,
    write methods, interesting/reflected params). This is the existing intel
    interest score, surfaced here unchanged.
  * **confidence** — *how much an analyst should believe it is real and reachable*
    (discovery provenance, observed status code, whether it survived dedup).

Keeping the two separate is deliberate: a high-importance endpoint discovered
only as a string inside a JS bundle is interesting *but unverified*, and the
dashboard should say so rather than conflating the two.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.models import Endpoint
from .confidence import Confidence, ConfidenceLevel
from .normalize import dedup_key

if TYPE_CHECKING:  # avoid a hard validation→analysis dependency
    from ..analysis.intel import EndpointIntel

# Trust weighting by how the endpoint was discovered.
_PROVENANCE_BASE: dict[str, float] = {
    "crawl": 65.0,     # actually fetched during the crawl
    "form": 60.0,      # parsed from a real <form> on a fetched page
    "sitemap": 55.0,   # declared by the server's sitemap
    "robots": 45.0,    # mentioned in robots.txt (declared, not fetched)
    "js": 40.0,        # a string inside JavaScript — plausible but unconfirmed
    "manual": 70.0,    # analyst-provided
}
_DEFAULT_PROVENANCE_BASE = 45.0

# Status-code signals: a live 2xx/3xx confirms reachability; 404/410 refutes it.
_LIVE_STATUSES = range(200, 400)
_DEAD_STATUSES = frozenset({404, 410})


@dataclass
class ValidatedEndpoint:
    """An endpoint enriched with confidence + importance + verification state."""

    endpoint: Endpoint
    confidence: Confidence
    importance: int = 0
    classes: list[str] = field(default_factory=list)
    duplicates: int = 0  # how many raw records collapsed into this one

    @property
    def url(self) -> str:
        return self.endpoint.url

    @property
    def method(self) -> str:
        return self.endpoint.method.value

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
    def trustworthy(self) -> bool:
        return self.confidence.trustworthy


def validate_endpoint(intel: EndpointIntel, *, duplicates: int = 0) -> ValidatedEndpoint:
    """Derive a confidence assessment for a single classified endpoint."""
    ep = intel.endpoint
    provenance = (ep.discovered_via or "crawl").lower()
    conf = Confidence(base=_PROVENANCE_BASE.get(provenance, _DEFAULT_PROVENANCE_BASE))
    conf.add("provenance", 0.0, f"discovered via {provenance}", source=f"discovery:{provenance}")

    # Observed status code is the strongest reachability signal we have.
    status = ep.status
    if status is not None:
        if status in _DEAD_STATUSES:
            conf.refute(f"http:{status}", f"server returned {status} (dead route)")
        elif status in _LIVE_STATUSES:
            conf.verify(f"http:{status}", f"server returned {status} (reachable)")
        elif status >= 500:
            conf.add("server_error", 5.0, f"server returned {status}", source=f"http:{status}")

    # Corroboration: multiple raw records collapsing here means several signals
    # independently pointed at this route.
    if duplicates:
        conf.add("corroboration", min(15.0, 5.0 * duplicates),
                 f"{duplicates} duplicate discoveries merged", source="dedup")

    # A clearly-classified endpoint is more likely to be a meaningful route than
    # an unclassified generic string.
    primary = intel.primary_class.value if intel.classes else "generic"
    if primary not in ("generic", "static"):
        conf.add("classified", 6.0, f"classified as {primary}", source="intel")
    if primary == "static":
        conf.penalize("static", 8.0, "static asset (low analyst value)", source="intel")

    return ValidatedEndpoint(
        endpoint=ep,
        confidence=conf,
        importance=intel.score,
        classes=[c.value for c in intel.classes],
        duplicates=duplicates,
    )


def deduplicate_endpoints(endpoints: list[Endpoint]) -> tuple[list[Endpoint], dict[str, int]]:
    """Collapse logically-duplicate endpoints, returning (unique, counts).

    Records sharing a :func:`dedup_key` are merged: parameters are unioned, the
    most informative status is kept, and a crawl-confirmed record is preferred
    over a JS-inferred one. ``counts`` maps each surviving dedup key to how many
    raw records collapsed into it (used as a corroboration signal).
    """
    order: list[str] = []
    merged: dict[str, Endpoint] = {}
    counts: dict[str, int] = {}

    for ep in endpoints:
        key = dedup_key(ep.method.value, ep.url, [p.name for p in ep.params])
        counts[key] = counts.get(key, 0) + 1
        if key not in merged:
            merged[key] = ep.model_copy(deep=True)
            order.append(key)
            continue
        existing = merged[key]
        # union parameters by their location:name key
        have = {p.key() for p in existing.params}
        for p in ep.params:
            if p.key() not in have:
                existing.params.append(p)
                have.add(p.key())
        # keep the most informative status (prefer a concrete live/dead code)
        if existing.status is None and ep.status is not None:
            existing.status = ep.status
        # prefer crawl provenance over inferred sources
        if existing.discovered_via == "js" and ep.discovered_via in ("crawl", "form", "sitemap"):
            existing.discovered_via = ep.discovered_via

    return [merged[k] for k in order], counts


def validate_intel(intels: list[EndpointIntel]) -> list[ValidatedEndpoint]:
    """Validate a list of classified endpoints, sorted most-trustworthy first.

    Duplicate suppression runs first (on the underlying endpoints) so corroboration
    counts feed the confidence of each surviving endpoint. Sorting is stable and
    deterministic: by confidence, then importance, then URL.
    """
    if not intels:
        return []
    raw_eps = [i.endpoint for i in intels]
    _, counts = deduplicate_endpoints(raw_eps)

    # index intels by dedup key, keeping the highest-importance representative
    chosen: dict[str, EndpointIntel] = {}
    order: list[str] = []
    for i in intels:
        ep = i.endpoint
        key = dedup_key(ep.method.value, ep.url, [p.name for p in ep.params])
        if key not in chosen:
            chosen[key] = i
            order.append(key)
        elif i.score > chosen[key].score:
            chosen[key] = i

    validated = [
        validate_endpoint(chosen[key], duplicates=max(0, counts.get(key, 1) - 1))
        for key in order
    ]
    validated.sort(key=lambda v: (-v.score, -v.importance, v.url))
    return validated
