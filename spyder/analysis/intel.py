"""Recon intelligence: classify, score, and summarize discovered attack surface.

This module is the analytical brain behind SPYDER's dashboard. It takes the raw
``Endpoint`` inventory the crawler produced and derives *intelligence* a human
analyst cares about: which endpoints are authentication, admin, API, GraphQL, or
upload surfaces; how interesting each one is; what parameters recur; and what the
overall attack surface looks like.

Strictly observational and read-only — it classifies and ranks reconnaissance
data. It does not generate or suggest exploitation.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse

from ..core.models import Endpoint, Finding, HTTPMethod
from .fingerprint import Technology

# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------


class EndpointClass(StrEnum):
    AUTH = "auth"
    ADMIN = "admin"
    API = "api"
    GRAPHQL = "graphql"
    UPLOAD = "upload"
    PAYMENT = "payment"
    STATIC = "static"
    GENERIC = "generic"


# Path keyword signatures (matched against the lowercased URL path).
_CLASS_KEYWORDS: dict[EndpointClass, tuple[str, ...]] = {
    EndpointClass.AUTH: (
        "login", "logout", "signin", "sign-in", "signup", "sign-up", "register",
        "auth", "oauth", "sso", "saml", "token", "session", "password", "passwd",
        "credential", "reset", "forgot", "mfa", "2fa", "otp", "verify",
    ),
    EndpointClass.ADMIN: (
        "admin", "administrator", "manage", "management", "console", "backend",
        "wp-admin", "superuser", "/root", "internal", "staff", "moderator",
    ),
    EndpointClass.API: (
        "/api", "/rest", "/v1", "/v2", "/v3", "/json", "swagger", "openapi",
        "graphql",  # also caught by GRAPHQL; API is the broader surface
    ),
    EndpointClass.GRAPHQL: ("graphql", "graphiql", "/gql", "playground"),
    EndpointClass.UPLOAD: (
        "upload", "import", "attachment", "/file", "/files", "media", "avatar",
        "document", "/blob", "ingest",
    ),
    EndpointClass.PAYMENT: (
        "payment", "checkout", "billing", "invoice", "charge", "subscription",
        "stripe", "paypal", "/card", "wallet", "refund",
    ),
}

_STATIC_EXTENSIONS = (
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".pdf", ".zip",
)

# Parameter names that warrant analyst attention (recon signal, not payloads).
_INTERESTING_PARAMS: frozenset[str] = frozenset({
    "id", "uid", "user", "user_id", "userid", "account", "acct",
    "redirect", "redirect_uri", "redirect_url", "url", "uri", "next", "return",
    "returnurl", "callback", "continue", "dest", "destination",
    "file", "filename", "filepath", "path", "dir", "folder", "document", "doc",
    "template", "include", "page", "view", "load",
    "cmd", "exec", "command", "run", "query", "q", "search", "filter",
    "token", "key", "api_key", "apikey", "access_token", "auth", "session",
    "debug", "test", "admin", "role", "is_admin", "privilege",
    "email", "to", "from", "host", "domain", "server", "port", "proxy",
})

_WRITE_METHODS = frozenset({
    HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE,
})

# Interest-score weights per classification.
_CLASS_WEIGHT: dict[EndpointClass, int] = {
    EndpointClass.ADMIN: 35,
    EndpointClass.AUTH: 30,
    EndpointClass.GRAPHQL: 28,
    EndpointClass.PAYMENT: 28,
    EndpointClass.UPLOAD: 25,
    EndpointClass.API: 15,
    EndpointClass.GENERIC: 0,
    EndpointClass.STATIC: -25,
}


@dataclass
class EndpointIntel:
    """Derived intelligence for a single endpoint."""

    endpoint: Endpoint
    classes: list[EndpointClass] = field(default_factory=list)
    score: int = 0
    tags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return self.endpoint.url

    @property
    def method(self) -> str:
        return self.endpoint.method.value

    @property
    def primary_class(self) -> EndpointClass:
        return self.classes[0] if self.classes else EndpointClass.GENERIC

    @property
    def high_interest(self) -> bool:
        return self.score >= 40


def _path_of(url: str) -> str:
    return (urlparse(url).path or "/").lower()


def _matched_classes(url: str) -> list[EndpointClass]:
    path = _path_of(url)
    if path.endswith(_STATIC_EXTENSIONS):
        return [EndpointClass.STATIC]
    matched: list[EndpointClass] = []
    for cls, keywords in _CLASS_KEYWORDS.items():
        if any(kw in path for kw in keywords):
            matched.append(cls)
    return matched


def classify_endpoint(ep: Endpoint) -> EndpointIntel:
    """Classify and score a single endpoint."""
    intel = EndpointIntel(endpoint=ep)
    classes = _matched_classes(ep.url)

    score = 0
    for cls in classes:
        score += _CLASS_WEIGHT.get(cls, 0)
        intel.reasons.append(f"path matches {cls.value}")

    # write methods widen the surface
    if ep.method in _WRITE_METHODS:
        score += 15
        intel.tags.append(f"method:{ep.method.value}")
        intel.reasons.append(f"{ep.method.value} (state-changing)")

    # parameter signals
    interesting = sorted({
        p.name.lower() for p in ep.params if p.name.lower() in _INTERESTING_PARAMS
    })
    reflected = [p.name for p in ep.params if p.reflected]
    if ep.params:
        score += 5
    for name in interesting:
        score += 8
        intel.tags.append(f"param:{name}")
    if interesting:
        intel.reasons.append("interesting params: " + ", ".join(interesting))
    if reflected:
        score += 10 * min(len(reflected), 3)
        intel.tags.append("reflected")
        intel.reasons.append("reflected params: " + ", ".join(reflected))

    if not classes:
        classes = [EndpointClass.GENERIC]

    # demote pure static assets
    if EndpointClass.STATIC in classes:
        intel.tags.append("static")

    intel.classes = classes
    intel.score = max(0, min(100, score))
    return intel


def classify_all(endpoints: list[Endpoint]) -> list[EndpointIntel]:
    """Classify every endpoint, sorted by interest score (descending)."""
    intels = [classify_endpoint(ep) for ep in endpoints]
    intels.sort(key=lambda i: i.score, reverse=True)
    return intels


def high_interest(intels: list[EndpointIntel], threshold: int = 40) -> list[EndpointIntel]:
    """Filter to the high-interest endpoints worth manual review first."""
    return [i for i in intels if i.score >= threshold]


# ---------------------------------------------------------------------------
# Parameter analytics
# ---------------------------------------------------------------------------


@dataclass
class ParamAnalytics:
    total: int = 0
    unique_names: int = 0
    by_location: dict[str, int] = field(default_factory=dict)
    reflected: int = 0
    interesting: list[tuple[str, int]] = field(default_factory=list)


def analyze_parameters(endpoints: list[Endpoint]) -> ParamAnalytics:
    """Aggregate parameter statistics across the inventory."""
    names: Counter[str] = Counter()
    by_location: Counter[str] = Counter()
    interesting: Counter[str] = Counter()
    total = 0
    reflected = 0
    for ep in endpoints:
        for p in ep.params:
            total += 1
            names[p.name.lower()] += 1
            by_location[p.location.value] += 1
            if p.reflected:
                reflected += 1
            if p.name.lower() in _INTERESTING_PARAMS:
                interesting[p.name.lower()] += 1
    return ParamAnalytics(
        total=total,
        unique_names=len(names),
        by_location=dict(by_location),
        reflected=reflected,
        interesting=interesting.most_common(10),
    )


# ---------------------------------------------------------------------------
# Attack surface metrics
# ---------------------------------------------------------------------------


@dataclass
class AttackSurface:
    total_endpoints: int = 0
    with_params: int = 0
    write_endpoints: int = 0
    reflected_params: int = 0
    high_interest: int = 0
    by_method: dict[str, int] = field(default_factory=dict)
    by_class: dict[str, int] = field(default_factory=dict)


def attack_surface(endpoints: list[Endpoint], intels: list[EndpointIntel] | None = None) -> AttackSurface:
    """Compute high-level attack-surface metrics from the inventory."""
    intels = intels if intels is not None else classify_all(endpoints)
    by_method: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    with_params = 0
    write_endpoints = 0
    reflected = 0
    for ep in endpoints:
        by_method[ep.method.value] += 1
        if ep.params:
            with_params += 1
        if ep.method in _WRITE_METHODS:
            write_endpoints += 1
        reflected += sum(1 for p in ep.params if p.reflected)
    for intel in intels:
        for cls in intel.classes:
            by_class[cls.value] += 1
    return AttackSurface(
        total_endpoints=len(endpoints),
        with_params=with_params,
        write_endpoints=write_endpoints,
        reflected_params=reflected,
        high_interest=sum(1 for i in intels if i.high_interest),
        by_method=dict(by_method),
        by_class=dict(by_class),
    )


# ---------------------------------------------------------------------------
# Technology summarization
# ---------------------------------------------------------------------------


@dataclass
class TechSummary:
    technologies: dict[str, str] = field(default_factory=dict)
    #: Full technology entities with their evidence, when the finding carried
    #: them. This is the form the confidence model scores.
    entities: list[Technology] = field(default_factory=list)
    #: Technology name → how many separate responses reported it.
    occurrences: dict[str, int] = field(default_factory=dict)
    waf: list[str] = field(default_factory=list)
    dbms: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.technologies or self.waf or self.dbms)


def summarize_technologies(findings: list[Finding]) -> TechSummary:
    """Aggregate passive-fingerprint findings into a technology summary.

    Reads the evidence of any finding carrying ``technology_entities`` /
    ``technologies`` / ``waf_hints`` / ``dbms_hints`` keys (as produced by the
    orchestrator's passive fingerprint). Entities seen in several responses are
    merged, unioning their evidence and counting the responses — which is what
    lets the confidence model reward repetition without inventing corroboration.
    """
    summary = TechSummary()
    waf: set[str] = set()
    dbms: set[str] = set()
    merged: dict[str, Technology] = {}
    for f in findings:
        ev = f.evidence or {}
        entities = ev.get("technology_entities")
        if isinstance(entities, list):
            for raw in entities:
                if not isinstance(raw, dict):
                    continue
                tech = Technology.from_dict(raw)
                if not tech.name:
                    continue
                summary.occurrences[tech.name] = summary.occurrences.get(tech.name, 0) + 1
                existing = merged.get(tech.name)
                if existing is None:
                    merged[tech.name] = tech
                    continue
                if tech.version and not existing.version:
                    existing.version = tech.version
                for e in tech.evidence:
                    if e not in existing.evidence:
                        existing.evidence.append(e)
        techs = ev.get("technologies")
        if isinstance(techs, dict):
            summary.technologies.update({k: str(v) for k, v in techs.items()})
    for tech in merged.values():
        tech.evidence.sort()
    summary.entities = sorted(
        merged.values(),
        key=lambda t: (-max((e.weight for e in t.evidence), default=0.0), t.name),
    )
    for f in findings:
        ev = f.evidence or {}
        for w in ev.get("waf_hints", []) or []:
            waf.add(str(w))
        for d in ev.get("dbms_hints", []) or []:
            dbms.add(str(d))
    summary.waf = sorted(waf)
    summary.dbms = sorted(dbms)
    return summary
