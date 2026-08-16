"""Core pydantic models shared across SPYDER subsystems."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, HttpUrl, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class HTTPMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class ParamLocation(StrEnum):
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class Parameter(BaseModel):
    """A discovered input parameter on an endpoint."""

    name: str
    location: ParamLocation
    example: str | None = None
    reflected: bool = False
    source: str = "crawl"  # crawl | form | js | sitemap | manual

    def key(self) -> str:
        return f"{self.location.value}:{self.name}"


class Endpoint(BaseModel):
    """A discovered endpoint with its method and parameters."""

    url: str
    method: HTTPMethod = HTTPMethod.GET
    params: list[Parameter] = Field(default_factory=list)
    content_type: str | None = None
    discovered_via: str = "crawl"
    status: int | None = None
    first_seen: datetime = Field(default_factory=_utcnow)

    @field_validator("url")
    @classmethod
    def _strip_fragment(cls, v: str) -> str:
        parsed = urlparse(v)
        return parsed._replace(fragment="").geturl()

    def fingerprint(self) -> str:
        parts = sorted(p.key() for p in self.params)
        raw = f"{self.method.value} {self.url} {'|'.join(parts)}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


class Finding(BaseModel):
    """An analyst-facing observation. SPYDER surfaces observations, not exploits.

    A finding is only useful if a reader can audit it, so every field that makes
    it auditable is part of the model rather than free text in the description:
    what was observed (``evidence``), where (``endpoint``), who says so
    (``source``), how much to trust it (``confidence``/``confidence_score``),
    what class of weakness it is (``cwe``/``owasp``), what to do about it
    (``remediation``), and where to read more (``references``).

    ``key`` ties the finding to :mod:`spyder.reporting.catalogue`, which owns the
    CWE/OWASP mappings so they are reviewable in one place instead of being
    restated at each call site.
    """

    title: str
    severity: Severity = Severity.INFO
    endpoint: str | None = None
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    #: Catalogue key; "" for findings raised outside the catalogue (e.g. a
    #: connector relaying another tool's result).
    key: str = ""
    #: Reliability band — confirmed | high | medium | low | noise. Passive
    #: observation tops out at "high"; see spyder.validation.confidence.
    confidence: str = "medium"
    confidence_score: int = 50
    source: str = "SPYDER"  # SPYDER | SPYDER:<connector> | SPYDER:plugin:<name>
    created: datetime = Field(default_factory=_utcnow)

    def fingerprint(self) -> str:
        """A stable identity for a finding, independent of when it was observed.

        Two findings with the same source, severity, title and endpoint describe
        the same observation, so re-running a scan refreshes the existing record
        instead of appending an identical duplicate. Timestamp and volatile
        evidence are deliberately excluded from the identity.
        """
        raw = f"{self.source}|{self.severity.value}|{self.title}|{self.endpoint or ''}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


class Target(BaseModel):
    """A scan target with scope constraints."""

    base_url: HttpUrl
    scope_hosts: list[str] = Field(default_factory=list)
    include_subdomains: bool = True

    @property
    def host(self) -> str:
        return urlparse(str(self.base_url)).netloc.split(":")[0]


def normalize_url(raw: str) -> str:
    """Accept bare hosts (example.com) by defaulting them to https://."""
    raw = (raw or "").strip()
    if raw and "://" not in raw:
        return "https://" + raw
    return raw


def parse_target(raw: str, scope_hosts: list[str] | None = None) -> Target:
    """Build a ``Target`` from user input, raising a clean ``ValueError`` on bad URLs.

    Callers surface the ValueError message directly to the operator instead of
    letting a raw pydantic ``ValidationError`` traceback escape. A bare, schemeless
    single word with no dot (e.g. ``notaurl``) is rejected rather than silently
    promoted to ``https://notaurl``; a real domain or explicitly-schemed URL passes.
    """
    from pydantic import ValidationError

    cleaned = (raw or "").strip()
    had_scheme = "://" in cleaned
    if not cleaned or (not had_scheme and "." not in cleaned):
        raise ValueError(
            f"Invalid target: {raw!r} — expected a URL like https://example.com"
        )
    try:
        # pydantic validates/coerces the str into an HttpUrl at construction time.
        return Target(base_url=normalize_url(cleaned), scope_hosts=scope_hosts or [])  # type: ignore[arg-type]
    except ValidationError as exc:
        raise ValueError(
            f"Invalid target: {raw!r} — expected a URL like https://example.com"
        ) from exc
