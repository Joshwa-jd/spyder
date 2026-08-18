"""JavaScript reconnaissance intelligence engine.

Parses JavaScript discovered during crawling and mines it for attack-surface
intelligence: hidden endpoints, API routes, GraphQL references, websocket URLs,
source-map references, cloud-bucket references, hardcoded domains, and high-signal
secret patterns (JWTs, API keys, Firebase/AWS/OAuth markers).

Strictly observational. It reads JavaScript a server already served and reports
what it finds for an analyst to review — it does not exfiltrate, authenticate,
or act on any discovered value. Secret *values* are redacted before storage.

Layout:
  * pure extractors           — regex miners over JS source text (no I/O)
  * JsIntel / Secret          — structured, mergeable results
  * JsReconEngine             — async fetch+analyze pipeline over the HTTP client
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..core.events import EventBus, EventType
from ..core.models import Endpoint, HTTPMethod
from ..http.client import HTTPClient
from ..utils.logging import get_logger
from ..utils.scope import ScopeGuard
from ..validation.secrets import validate_secret_value

log = get_logger("jsintel")

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------

# Quoted relative/absolute paths: "/api/v1/users", '/login?x=1'
_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./~]+(?:\?[^'"`\s]*)?)['"`]""")
# Absolute http(s) URLs
_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
# fetch()/axios.get()/xhr.open() call targets
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|\.get|\.post|\.put|\.delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.I,
)
# websockets
_WS_RE = re.compile(r"""wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
_WS_CTOR_RE = re.compile(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""", re.I)
# source maps
_SOURCEMAP_RE = re.compile(r"""sourceMappingURL=([^\s'"*]+)""")
_MAP_REF_RE = re.compile(r"""['"`]([^'"`]+\.js\.map)['"`]""")
# cloud buckets
_S3_RE = re.compile(r"""[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9.\-]{3,}""", re.I)
_GCS_RE = re.compile(r"""(?:storage\.googleapis\.com/[A-Za-z0-9._\-]+|[a-z0-9._\-]+\.storage\.googleapis\.com)""", re.I)
_AZURE_RE = re.compile(r"""[a-z0-9]+\.blob\.core\.windows\.net""", re.I)
# hardcoded domains (host-like tokens)
_DOMAIN_RE = re.compile(r"""\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,18}\b""")
# graphql markers
_GRAPHQL_RE = re.compile(r"""(/graph(?:ql|iql)|__schema|operationName|gql`)""", re.I)
# oauth markers
_OAUTH_RE = re.compile(r"""(/oauth/(?:authorize|token)|response_type=|client_id=)""", re.I)

# Common non-domain noise to drop from domain extraction.
_DOMAIN_STOPWORDS = frozenset({
    "min.js", "bundle.js", "chunk.js", "vendor.js", "main.js", "app.js",
    "index.js", "runtime.js", "polyfills.js", "styles.css",
})
_FILE_SUFFIXES = (".js", ".css", ".map", ".json", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ts", ".vue")

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------


@dataclass
class _SecretPattern:
    kind: str
    regex: re.Pattern
    confidence: str
    #: 0 = the whole match is the secret. Otherwise the secret is the first
    #: capturing group that participated — patterns offering alternative shapes
    #: (a quoted value *or* a bare one) capture into different groups.
    group: int = 0

    def value_of(self, m: re.Match) -> str:
        if not self.group:
            return m.group(0)
        return next((g for g in m.groups() if g is not None), "")


_SECRET_PATTERNS: tuple[_SecretPattern, ...] = (
    _SecretPattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high"),
    _SecretPattern("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    # The access key *ID* is an identifier; this is the credential it pairs with.
    # A bare 40-char base64-ish run is far too common to claim on shape alone, so
    # the match is anchored to an AWS secret-key assignment.
    _SecretPattern(
        "aws_secret_access_key",
        re.compile(r"""(?i)aws_?secret_?(?:access_?)?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"""),
        "high",
        group=1,
    ),
    _SecretPattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    # xoxb/xoxp/… bot & user tokens, xoxe refresh tokens, and xapp app-level tokens.
    _SecretPattern("slack_token", re.compile(r"\b(?:xox[baprse]|xapp)-[0-9A-Za-z\-]{10,}\b"), "high"),
    # An incoming-webhook URL authenticates by possession: it is a credential.
    _SecretPattern(
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]{20,}"),
        "high",
    ),
    _SecretPattern("stripe_key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"), "high"),
    # Classic PATs (gh?_ + 36) and fine-grained PATs (github_pat_ + 22 + _ + tail).
    _SecretPattern(
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{20,})\b"),
        "high",
    ),
    # Twilio API Key SID. The Account SID (AC…) is deliberately *not* matched:
    # it is published in dashboards and URLs, so claiming it as a secret would
    # be a false positive.
    _SecretPattern("twilio_api_key", re.compile(r"\bSK[0-9a-f]{32}\b"), "high"),
    _SecretPattern("firebase_db", re.compile(r"\b[a-z0-9\-]+\.firebaseio\.com\b", re.I), "medium"),
    _SecretPattern("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "high"),
    # Quoted *or* bare assignments — `.env` files are a primary leak vector and
    # never quote their values. A bare value must end at a real boundary so the
    # match cannot run past the end of the assignment.
    _SecretPattern(
        "generic_secret",
        re.compile(
            r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)['"]?\s*[:=]\s*"""
            r"""(?:['"]([A-Za-z0-9_\-./+]{12,})['"]|([A-Za-z0-9_\-./+]{12,})(?=[\s;,)'"]|$))"""
        ),
        "medium",
        group=1,
    ),
)


@dataclass(frozen=True)
class Secret:
    """A redacted secret-pattern match found in JavaScript.

    Carries validation metadata derived from the *unredacted* value at extraction
    time (entropy, placeholder checks): a numeric ``score``, a confidence
    ``level``, and a ``reasons`` trace explaining the verdict. The raw value is
    never stored — only ``value`` (redacted) survives.
    """

    kind: str
    value: str          # redacted
    confidence: str = "medium"
    source: str | None = None
    score: int = 0
    level: str = "medium"
    reasons: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)

    @property
    def verified(self) -> bool:
        return self.level == "confirmed"


def _redact(raw: str) -> str:
    raw = raw.strip()
    if len(raw) <= 8:
        return raw[0] + "…" if raw else "…"
    return f"{raw[:4]}…{raw[-2:]} ({len(raw)} chars)"


# ---------------------------------------------------------------------------
# JsIntel — structured, mergeable result
# ---------------------------------------------------------------------------


@dataclass
class JsIntel:
    source: str | None = None
    endpoints: set[str] = field(default_factory=set)
    api_routes: set[str] = field(default_factory=set)
    graphql: set[str] = field(default_factory=set)
    websockets: set[str] = field(default_factory=set)
    source_maps: set[str] = field(default_factory=set)
    buckets: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    oauth: set[str] = field(default_factory=set)
    secrets: list[Secret] = field(default_factory=list)

    def merge(self, other: JsIntel) -> JsIntel:
        self.endpoints |= other.endpoints
        self.api_routes |= other.api_routes
        self.graphql |= other.graphql
        self.websockets |= other.websockets
        self.source_maps |= other.source_maps
        self.buckets |= other.buckets
        self.domains |= other.domains
        self.oauth |= other.oauth
        seen = {s.key for s in self.secrets}
        for s in other.secrets:
            if s.key not in seen:
                self.secrets.append(s)
                seen.add(s.key)
        return self

    @property
    def counts(self) -> dict[str, int]:
        return {
            "endpoints": len(self.endpoints),
            "api_routes": len(self.api_routes),
            "graphql": len(self.graphql),
            "websockets": len(self.websockets),
            "source_maps": len(self.source_maps),
            "buckets": len(self.buckets),
            "domains": len(self.domains),
            "oauth": len(self.oauth),
            "secrets": len(self.secrets),
            "verified_secrets": self.verified_secrets,
        }

    @property
    def verified_secrets(self) -> int:
        """Secrets whose validation reached confirmed/high confidence."""
        return sum(1 for s in self.secrets if s.level in ("confirmed", "high"))

    @property
    def secret_levels(self) -> dict[str, int]:
        """Confidence-level breakdown of surviving (non-suppressed) secrets."""
        out: dict[str, int] = {}
        for s in self.secrets:
            out[s.level] = out.get(s.level, 0) + 1
        return out


# ---------------------------------------------------------------------------
# Pure extraction
# ---------------------------------------------------------------------------


def _normalize_route(raw: str) -> str | None:
    """Normalize a discovered route/path; drop noise. Returns None to discard."""
    raw = raw.strip().strip("'\"`")
    if not raw or "${" in raw or raw.startswith(("data:", "javascript:", "mailto:", "blob:", "#")):
        return None
    if raw in ("/", "//"):
        return None
    return raw


def _looks_like_api(route: str) -> bool:
    low = route.lower()
    return any(seg in low for seg in ("/api", "/rest", "/v1", "/v2", "/v3", "/graphql", "/gql"))


def extract_endpoints(js: str) -> set[str]:
    out: set[str] = set()
    for m in _PATH_RE.finditer(js):
        r = _normalize_route(m.group(1))
        if r:
            out.add(r)
    for m in _CALL_RE.finditer(js):
        r = _normalize_route(m.group(1))
        if r and (r.startswith("/") or r.startswith("http")):
            out.add(r)
    for m in _URL_RE.finditer(js):
        out.add(m.group(0).rstrip("\\\"'),;"))
    return out


def extract_secrets(js: str, source: str | None = None) -> list[Secret]:
    """Extract and *validate* candidate secrets, suppressing fakes/placeholders.

    Each regex match is scored by :func:`validate_secret_value` against the raw
    value (entropy, placeholder detection). Matches the validator suppresses as
    noise are dropped here, so the inventory carries only credible candidates.
    """
    found: list[Secret] = []
    seen: set[tuple[str, str]] = set()
    for pat in _SECRET_PATTERNS:
        for m in pat.regex.finditer(js):
            raw = pat.value_of(m)
            verdict = validate_secret_value(pat.kind, raw, pat.confidence)
            if verdict.suppressed:  # fake-secret / placeholder suppression
                continue
            secret = Secret(
                kind=pat.kind,
                value=_redact(raw),
                confidence=pat.confidence,
                source=source,
                score=verdict.score,
                level=verdict.level.value,
                reasons=tuple(verdict.reasons),
            )
            if secret.key not in seen:
                found.append(secret)
                seen.add(secret.key)
    return found


def _filter_domains(raw_domains: set[str]) -> set[str]:
    out: set[str] = set()
    for d in raw_domains:
        dl = d.lower()
        if dl in _DOMAIN_STOPWORDS or dl.endswith(_FILE_SUFFIXES):
            continue
        out.add(dl)
    return out


def analyze_js(js: str, source: str | None = None) -> JsIntel:
    """Mine a single JavaScript source for recon intelligence."""
    intel = JsIntel(source=source)
    endpoints = extract_endpoints(js)
    intel.endpoints = endpoints
    intel.api_routes = {r for r in endpoints if _looks_like_api(r)}

    if _GRAPHQL_RE.search(js):
        intel.graphql = {r for r in endpoints if "graph" in r.lower()} or {"<graphql usage detected>"}
    intel.websockets = set(_WS_RE.findall(js)) | {
        m.group(1) for m in _WS_CTOR_RE.finditer(js)
    }
    intel.source_maps = set(_SOURCEMAP_RE.findall(js)) | set(_MAP_REF_RE.findall(js))
    intel.buckets = set(_S3_RE.findall(js)) | set(_GCS_RE.findall(js)) | set(_AZURE_RE.findall(js))
    intel.domains = _filter_domains(set(_DOMAIN_RE.findall(js)))
    intel.oauth = {m.group(0) for m in _OAUTH_RE.finditer(js)}
    intel.secrets = extract_secrets(js, source)
    return intel


def routes_to_endpoints(intel: JsIntel, base_url: str, scope: ScopeGuard) -> list[Endpoint]:
    """Resolve in-scope JS routes into Endpoint records (discovered_via='js')."""
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    for route in intel.endpoints:
        resolved = route if route.startswith("http") else urljoin(base_url, route)
        if not resolved.startswith("http") or not scope.in_scope(resolved):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        endpoints.append(Endpoint(url=resolved, method=HTTPMethod.GET, discovered_via="js"))
    return endpoints


# ---------------------------------------------------------------------------
# Async fetch + analyze pipeline
# ---------------------------------------------------------------------------


@dataclass
class JsReconResult:
    files_analyzed: int = 0
    intel: JsIntel = field(default_factory=JsIntel)
    endpoints: list[Endpoint] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = self.intel.counts
        c["files"] = self.files_analyzed
        return c


class JsReconEngine:
    """Fetches discovered JS files concurrently and aggregates intelligence."""

    def __init__(
        self,
        client: HTTPClient,
        scope: ScopeGuard,
        events: EventBus | None = None,
        concurrency: int = 8,
        max_files: int = 60,
        max_bytes: int = 3_000_000,
    ):
        self.client = client
        self.scope = scope
        self.events = events
        self.concurrency = concurrency
        self.max_files = max_files
        self.max_bytes = max_bytes

    def _emit(self, type: EventType, message: str, **data) -> None:
        if self.events:
            self.events.emit(type, message, source="jsintel", **data)

    async def _analyze_one(self, url: str, base_url: str, sem: asyncio.Semaphore) -> JsIntel:
        async with sem:
            try:
                txn = await self.client.get(url)
            except Exception as exc:  # network issues must not abort the batch
                log.debug("js fetch failed %s: %s", url, exc)
                return JsIntel(source=url)
            body = (txn.body or "")[: self.max_bytes]
            intel = analyze_js(body, source=url)
            new_routes = len(intel.endpoints)
            if new_routes:
                self._emit(
                    EventType.JS_ROUTE,
                    f"{new_routes} routes · {url}",
                    url=url, routes=new_routes, api=len(intel.api_routes),
                )
            for secret in intel.secrets:
                self._emit(
                    EventType.SECRET,
                    f"{secret.kind} [{secret.level} · {secret.score}] in {url}",
                    kind=secret.kind, confidence=secret.confidence,
                    level=secret.level, score=secret.score, source=url,
                )
            return intel

    async def analyze_urls(self, js_urls: list[str], base_url: str) -> JsReconResult:
        urls = list(dict.fromkeys(js_urls))[: self.max_files]
        if not urls:
            return JsReconResult()
        self._emit(EventType.JS_ROUTE, f"analyzing {len(urls)} JS files", files=len(urls))
        sem = asyncio.Semaphore(self.concurrency)
        intels = await asyncio.gather(*(self._analyze_one(u, base_url, sem) for u in urls))

        merged = JsIntel()
        for i in intels:
            merged.merge(i)
        endpoints = routes_to_endpoints(merged, base_url, self.scope)
        result = JsReconResult(files_analyzed=len(urls), intel=merged, endpoints=endpoints)
        log.info(
            "js recon: %d files · %d routes · %d secrets · %d in-scope endpoints",
            result.files_analyzed, len(merged.endpoints), len(merged.secrets), len(endpoints),
        )
        return result
