"""Passive fingerprinting: evidence-driven technology identification.

Purely observational — pattern-matches what a server volunteers, sends no
probing payloads.

The engine reports **technology entities**, not header roles. A response
carrying ``Server: nginx/1.24.0`` yields the technology *Nginx* (version
1.24.0) supported by the evidence "Server: nginx/1.24.0", rather than the
opaque pair ``server -> nginx/1.24.0``. Every claim therefore names the thing
detected, the bytes that prove it, and where those bytes came from.

Two rules keep precision honest:

  * **Structural matching only.** A technology is claimed from a header value,
    a cookie *name*, a ``<meta name="generator">`` value, a markup attribute,
    or the URL of a referenced asset. The engine never scans prose for product
    names, so a page that merely *discusses* WordPress is not running it.
  * **Unknown is a real answer.** A response with no structural evidence
    produces no entities. Absence is reported, never filled in with a guess.

Scoring lives in :mod:`spyder.validation.fingerprint`; this module's job is to
find evidence and attribute it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..http.client import Transaction


class EvidenceSource(StrEnum):
    """Where a piece of evidence was observed.

    Independence matters more than the labels themselves: two observations from
    *different* sources corroborate each other, two from the same source do not
    (a header repeated twice is still one spoofable header).
    """

    HEADER = "http header"
    COOKIE = "cookie"
    HTML = "html"
    ASSET = "asset path"
    BODY = "body"


@dataclass(frozen=True, order=True)
class Evidence:
    """A single observation supporting a technology claim."""

    source: EvidenceSource
    kind: str      # short machine label, e.g. "server-header", "meta-generator"
    detail: str    # what was actually observed, e.g. "Server: nginx/1.24.0"
    weight: float  # standalone strength of this observation, 0-100

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "kind": self.kind,
            "detail": self.detail,
            "weight": self.weight,
        }


@dataclass
class Technology:
    """A detected technology and the evidence that proves it."""

    name: str
    category: str
    version: str | None = None
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def sources(self) -> tuple[EvidenceSource, ...]:
        """Distinct evidence sources, in a stable order."""
        seen: list[EvidenceSource] = []
        for e in self.evidence:
            if e.source not in seen:
                seen.append(e.source)
        return tuple(sorted(seen))

    @property
    def independent_sources(self) -> int:
        """How many *different* kinds of evidence attest to this technology."""
        return len(self.sources)

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Technology:
        tech = cls(
            name=str(d.get("name", "")),
            category=str(d.get("category", "")),
            version=d.get("version") or None,
        )
        for e in d.get("evidence", []) or []:
            try:
                source = EvidenceSource(e.get("source", ""))
            except ValueError:
                continue
            tech.evidence.append(
                Evidence(
                    source=source,
                    kind=str(e.get("kind", "")),
                    detail=str(e.get("detail", "")),
                    weight=float(e.get("weight", 0.0)),
                )
            )
        return tech


@dataclass
class Fingerprint:
    """Everything a single response volunteered about its stack."""

    entities: list[Technology] = field(default_factory=list)
    waf_hints: list[str] = field(default_factory=list)
    dbms_hints: list[str] = field(default_factory=list)

    @property
    def unknown(self) -> bool:
        """True when the response carried no technology evidence at all."""
        return not self.entities

    @property
    def technologies(self) -> dict[str, str]:
        """Technology name → version (empty string when none was stated)."""
        return {t.name: (t.version or "") for t in self.entities}


# ---------------------------------------------------------------------------
# Signature tables
#
# Weights are *standalone* strengths. None reaches the CONFIRMED bar on its
# own: a header is a server-volunteered fact but a spoofable one, so the top
# band here is 80 (HIGH) and promotion beyond it requires corroboration from an
# independent source. See spyder.validation.fingerprint.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Sig:
    tech: str
    category: str
    pattern: re.Pattern[str]
    weight: float
    kind: str
    key: str = ""  # header name for header signatures


def _sig(tech: str, category: str, key: str, pattern: str, weight: float, kind: str) -> _Sig:
    return _Sig(tech, category, re.compile(pattern, re.I), weight, kind, key)


#: Response headers. The value must match structurally, not merely contain the
#: product name — ``Server: my-nginx-proxy-notes`` must not claim Nginx.
_HEADER_SIGS: tuple[_Sig, ...] = (
    _sig("Nginx", "web server", "server", r"^nginx(?:/(?P<ver>[\d.]+))?", 80, "server-header"),
    _sig("Apache", "web server", "server", r"^Apache(?:/(?P<ver>[\d.]+))?", 80, "server-header"),
    _sig("IIS", "web server", "server", r"^Microsoft-IIS(?:/(?P<ver>[\d.]+))?", 80, "server-header"),
    _sig("LiteSpeed", "web server", "server", r"^LiteSpeed", 80, "server-header"),
    _sig("Caddy", "web server", "server", r"^Caddy", 80, "server-header"),
    _sig("Cloudflare", "cdn", "server", r"^cloudflare$", 80, "server-header"),
    _sig("PHP", "language", "x-powered-by", r"^PHP/(?P<ver>[\d.]+)", 78, "x-powered-by"),
    _sig("Express", "framework", "x-powered-by", r"^Express$", 78, "x-powered-by"),
    _sig("ASP.NET", "framework", "x-powered-by", r"^ASP\.NET", 78, "x-powered-by"),
    _sig("Next.js", "framework", "x-powered-by", r"^Next\.js", 78, "x-powered-by"),
    _sig("ASP.NET", "framework", "x-aspnet-version", r"^(?P<ver>[\d.]+)", 80, "aspnet-version"),
    _sig("Drupal", "cms", "x-generator", r"^Drupal(?:\s+(?P<ver>[\d.]+))?", 78, "x-generator"),
    _sig("Cloudflare", "cdn", "cf-ray", r".", 75, "cf-ray-header"),
    _sig("Cloudflare", "cdn", "cf-cache-status", r".", 70, "cf-cache-status-header"),
    _sig("Akamai", "cdn", "x-akamai-transformed", r".", 75, "akamai-header"),
    _sig("Amazon CloudFront", "cdn", "x-amz-cf-id", r".", 75, "cloudfront-header"),
    _sig("Varnish", "cache", "x-varnish", r".", 70, "varnish-header"),
)

#: Cookie *names*. A session-cookie name is a conventional hint, not proof —
#: anyone can name a cookie PHPSESSID — hence the deliberately modest weight.
_COOKIE_SIGS: tuple[_Sig, ...] = (
    _sig("PHP", "language", "", r"^PHPSESSID$", 50, "session-cookie"),
    _sig("Express", "framework", "", r"^connect\.sid$", 50, "session-cookie"),
    _sig("ASP.NET", "framework", "", r"^ASP\.NET_SessionId$", 50, "session-cookie"),
    _sig("Java", "language", "", r"^JSESSIONID$", 50, "session-cookie"),
    _sig("Laravel", "framework", "", r"^laravel_session$", 50, "session-cookie"),
    _sig("Django", "framework", "", r"^(?:csrftoken|django_language)$", 50, "session-cookie"),
    _sig("WordPress", "cms", "", r"^wordpress_(?:logged_in|sec|test_cookie)", 50, "session-cookie"),
    _sig("Cloudflare", "cdn", "", r"^(?:__cf_bm|cf_clearance|__cfduid)$", 50, "cloudflare-cookie"),
    _sig("Shopify", "ecommerce", "", r"^_shopify_", 50, "session-cookie"),
)

#: Products recognised in a ``<meta name="generator">`` value. The tag is the
#: page declaring its own authoring tool — strong, and structurally located.
_GENERATOR_SIGS: tuple[_Sig, ...] = (
    _sig("WordPress", "cms", "", r"^WordPress(?:\s+(?P<ver>[\d.]+))?", 78, "meta-generator"),
    _sig("Drupal", "cms", "", r"^Drupal(?:\s+(?P<ver>[\d.]+))?", 78, "meta-generator"),
    _sig("Joomla", "cms", "", r"^Joomla", 78, "meta-generator"),
    _sig("Hugo", "static site generator", "", r"^Hugo(?:\s+(?P<ver>[\d.]+))?", 78, "meta-generator"),
    _sig("Jekyll", "static site generator", "", r"^Jekyll", 78, "meta-generator"),
    _sig("Ghost", "cms", "", r"^Ghost(?:\s+(?P<ver>[\d.]+))?", 78, "meta-generator"),
    _sig("Wix", "cms", "", r"^Wix", 78, "meta-generator"),
)

#: Structural markup markers: framework-specific attributes and script hooks.
_MARKUP_SIGS: tuple[_Sig, ...] = (
    _sig("Angular", "framework", "", r"<[a-z][\w-]*[^>]*\sng-version=[\"'](?P<ver>[\d.]+)[\"']",
         65, "ng-version-attribute"),
    _sig("React", "framework", "", r"<[a-z][\w-]*[^>]*\sdata-reactroot[\s=>]", 65,
         "data-reactroot-attribute"),
    _sig("Next.js", "framework", "", r"<script[^>]+id=[\"']__NEXT_DATA__[\"']", 65,
         "next-data-script"),
    _sig("Nuxt.js", "framework", "", r"window\.__NUXT__\s*=", 65, "nuxt-global"),
    _sig("Vue.js", "framework", "", r"<[a-z][\w-]*[^>]*\sdata-v-[0-9a-f]{8}[\s=>]", 60,
         "scoped-style-attribute"),
    _sig("Django", "framework", "", r"<input[^>]+name=[\"']csrfmiddlewaretoken[\"']", 55,
         "csrf-input"),
)

#: Referenced asset URLs (src=/href= only). Framework-owned paths are strong
#: circumstantial evidence; an article *titled* "wordpress-vs-drupal" is not.
_ASSET_SIGS: tuple[_Sig, ...] = (
    _sig("WordPress", "cms", "", r"/wp-(?:content|includes)/", 55, "wp-asset-path"),
    _sig("Drupal", "cms", "", r"/sites/(?:default|all)/(?:files|modules|themes)/", 55,
         "drupal-asset-path"),
    _sig("jQuery", "library", "", r"/jquery[.-](?P<ver>\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
         60, "jquery-asset"),
    _sig("jQuery", "library", "", r"/jquery(?:\.min)?\.js(?:$|[?#])", 50, "jquery-asset"),
    _sig("Next.js", "framework", "", r"/_next/static/", 55, "next-asset-path"),
    _sig("Drupal", "cms", "", r"/core/misc/drupal\.js", 55, "drupal-asset-path"),
)

# DBMS error signatures (for passively recognizing leaked errors, not inducing them)
_DB_SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    "mysql": [re.compile(r"SQL syntax.*MySQL", re.I), re.compile(r"MySqlException", re.I)],
    "postgres": [re.compile(r"PostgreSQL.*ERROR", re.I), re.compile(r"PSQLException", re.I)],
    "mssql": [re.compile(r"Microsoft SQL Server", re.I), re.compile(r"System\.Data\.SqlClient", re.I)],
    "oracle": [re.compile(r"ORA-\d{5}", re.I), re.compile(r"Oracle.*Driver", re.I)],
    "sqlite": [re.compile(r"SQLite/JDBCDriver", re.I), re.compile(r"sqlite3\.OperationalError", re.I)],
}

_WAF_HEADER_HINTS: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai": ["x-akamai-transformed", "akamai-grn"],
    "aws": ["x-amz-cf-id", "x-amzn-requestid"],
    "imperva": ["x-iinfo", "incap_ses"],
    "f5": ["bigipserver", "x-waf-event"],
}

# --- extraction helpers ------------------------------------------------------

_META_GENERATOR = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]*\scontent=[\"'](?P<content>[^\"']*)[\"']", re.I
)
_META_GENERATOR_REV = re.compile(
    r"<meta[^>]+content=[\"'](?P<content>[^\"']*)[\"'][^>]*\sname=[\"']generator[\"']", re.I
)
_ASSET_URL = re.compile(r"\s(?:src|href)=[\"'](?P<url>[^\"']+)[\"']", re.I)
#: Cookie attributes, so a date-folded Set-Cookie does not look like a cookie.
_COOKIE_ATTRS = frozenset({
    "path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "version", "comment",
})
_COOKIE_NAME = re.compile(r"^\s*(?P<name>[^=;,\s]+)=")
_HTML_CT = re.compile(r"\b(?:text/html|application/xhtml)", re.I)


def _cookie_names(headers: dict[str, str]) -> list[str]:
    """Cookie names from Set-Cookie, coping with httpx's comma-folded form.

    httpx collapses repeated Set-Cookie headers into one comma-joined value, so
    the wire's two cookies arrive as one string. Segments that are really cookie
    *attributes* (the comma inside an Expires date) are discarded.
    """
    raw = headers.get("set-cookie", "")
    names: list[str] = []
    for segment in raw.split(","):
        m = _COOKIE_NAME.match(segment)
        if not m:
            continue
        name = m.group("name")
        if name.lower() in _COOKIE_ATTRS:
            continue
        if name not in names:
            names.append(name)
    return names


def _is_html(headers: dict[str, str]) -> bool:
    """Whether the body should be read as markup.

    Guards every HTML pass: a JSON document or a script that happens to contain
    the word "wordpress" must never produce a detection.
    """
    return bool(_HTML_CT.search(headers.get("content-type", "")))


def _meta_generator(body: str) -> str:
    for pattern in (_META_GENERATOR, _META_GENERATOR_REV):
        m = pattern.search(body)
        if m:
            return m.group("content").strip()
    return ""


def _asset_urls(body: str) -> list[str]:
    return [m.group("url") for m in _ASSET_URL.finditer(body)]


def _version_of(match: re.Match[str]) -> str | None:
    """The version a signature captured, if that signature captures one."""
    if "ver" not in match.re.groupindex:
        return None
    return match.group("ver") or None


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def fingerprint(txn: Transaction) -> Fingerprint:
    """Identify technologies a single response volunteered.

    Returns entities only where structural evidence exists; a response with no
    such evidence yields an empty :attr:`Fingerprint.entities` (Unknown).
    """
    headers = {k.lower(): v for k, v in txn.response_headers.items()}
    found: dict[str, Technology] = {}

    def record(sig: _Sig, source: EvidenceSource, detail: str, version: str | None) -> None:
        tech = found.get(sig.tech)
        if tech is None:
            tech = Technology(name=sig.tech, category=sig.category)
            found[sig.tech] = tech
        if version and not tech.version:
            tech.version = version
        ev = Evidence(source=source, kind=sig.kind, detail=detail, weight=sig.weight)
        if ev not in tech.evidence:
            tech.evidence.append(ev)

    # 1. Response headers.
    for sig in _HEADER_SIGS:
        value = headers.get(sig.key)
        if value is None:
            continue
        m = sig.pattern.search(value)
        if m:
            header_name = "-".join(p.capitalize() for p in sig.key.split("-"))
            record(sig, EvidenceSource.HEADER, f"{header_name}: {value}", _version_of(m))

    # 2. Cookie names.
    for name in _cookie_names(headers):
        for sig in _COOKIE_SIGS:
            if sig.pattern.search(name):
                record(sig, EvidenceSource.COOKIE, f"{name} cookie", None)

    # 3. Markup-derived evidence — HTML responses only.
    if _is_html(headers) and txn.body:
        generator = _meta_generator(txn.body)
        if generator:
            for sig in _GENERATOR_SIGS:
                m = sig.pattern.search(generator)
                if m:
                    record(sig, EvidenceSource.HTML,
                           f'<meta name="generator" content="{generator}">', _version_of(m))

        for sig in _MARKUP_SIGS:
            m = sig.pattern.search(txn.body)
            if m:
                source = EvidenceSource.BODY if sig.kind == "csrf-input" else EvidenceSource.HTML
                record(sig, source, f"{sig.kind} present in markup", _version_of(m))

        for url in _asset_urls(txn.body):
            for sig in _ASSET_SIGS:
                m = sig.pattern.search(url)
                if m:
                    record(sig, EvidenceSource.ASSET, f"asset {url}", _version_of(m))

    fp = Fingerprint()
    # Deterministic: highest standalone evidence first, then name.
    fp.entities = sorted(
        found.values(),
        key=lambda t: (-max(e.weight for e in t.evidence), t.name),
    )
    for tech in fp.entities:
        tech.evidence.sort()

    for waf, hints in _WAF_HEADER_HINTS.items():
        if any(h in headers for h in hints):
            fp.waf_hints.append(waf)
    for dbms, patterns in _DB_SIGNATURES.items():
        if any(p.search(txn.body) for p in patterns):
            fp.dbms_hints.append(dbms)
    return fp
