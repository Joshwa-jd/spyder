"""Deterministic URL / route normalization and de-duplication keys.

Endpoint inventories arrive noisy: the same logical route shows up as
``/api/Users/``, ``/api/users``, ``/api/users?b=2&a=1``, ``/api/users/42`` and
``/api/users/9d8c...``. Normalization collapses cosmetic variation so duplicate
suppression and confidence scoring operate on *logical* endpoints, not strings.

Everything here is pure and deterministic — identical inputs yield identical
canonical forms, which is what lets the dashboard's counts be trusted.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443"}
_MULTISLASH_RE = re.compile(r"/{2,}")

# Path segments that are clearly identifiers and should be templated to {id}.
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]{12,}$")        # long hex blobs / digests
_LONGNUM_MIX_RE = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{16,}$")  # tokens w/ digits

# Common cache-busting / session params that add no logical identity.
_VOLATILE_PARAMS: frozenset[str] = frozenset({
    "_", "_t", "ts", "t", "cb", "cachebust", "cache_bust", "v", "ver",
    "version", "rand", "random", "nocache", "timestamp",
})


def _is_identifier_segment(seg: str) -> bool:
    return bool(
        _NUMERIC_RE.match(seg)
        or _UUID_RE.match(seg)
        or _HEX_RE.match(seg)
        or _LONGNUM_MIX_RE.match(seg)
    )


def normalize_url(url: str, *, drop_query: bool = False) -> str:
    """Return a canonical form of ``url``.

    Lowercases scheme/host, strips default ports and fragments, collapses
    duplicate slashes, removes a trailing slash (except root), drops volatile
    query params, and sorts the remaining query for stable comparison.
    """
    if not url:
        return url
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    netloc = host.lower()
    if parts.port is not None and _DEFAULT_PORTS.get(scheme) != str(parts.port):
        netloc = f"{netloc}:{parts.port}"
    # userinfo is preserved if present (rare in recon, but keep it deterministic)
    if parts.username:
        cred = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{cred}@{netloc}"

    path = _MULTISLASH_RE.sub("/", parts.path or "")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/" if netloc else ""

    query = ""
    if not drop_query and parts.query:
        pairs = [
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in _VOLATILE_PARAMS
        ]
        pairs.sort()
        query = urlencode(pairs)

    return urlunsplit((scheme, netloc, path, query, ""))


def route_template(url_or_path: str) -> str:
    """Collapse identifier-like path segments to ``{id}`` for logical grouping.

    ``/api/users/42`` and ``/api/users/9f8c…`` both become ``/api/users/{id}``,
    so routes that differ only by a record id are recognized as one endpoint.
    Accepts either a full URL or a bare path; returns the same shape it received.
    """
    if "://" in url_or_path:
        parts = urlsplit(url_or_path)
        templated_path = route_template(parts.path or "/")
        return urlunsplit((parts.scheme, parts.netloc, templated_path, "", ""))

    path = _MULTISLASH_RE.sub("/", url_or_path or "/")
    segments = path.split("/")
    out = [
        "{id}" if seg and _is_identifier_segment(seg) else seg
        for seg in segments
    ]
    templated = "/".join(out)
    if len(templated) > 1 and templated.endswith("/"):
        templated = templated.rstrip("/")
    return templated or "/"


def dedup_key(method: str, url: str, param_names: list[str] | None = None) -> str:
    """A stable identity key for an endpoint, used for duplicate suppression.

    Two endpoints collapse to the same key when they share an HTTP method, a
    template-normalized route, and the same *set* of parameter names — regardless
    of record ids, query ordering, casing, or trailing slashes.

    Query-string parameters carried in ``url`` are folded into the name set
    alongside ``param_names``. Without this, the *same* logical route discovered
    two ways — e.g. ``/api/v1/orders?id=1`` parsed into an ``id`` parameter by the
    crawler versus mined from JavaScript as a bare URL string with no parsed
    params — would produce two different keys and survive as visible duplicates.
    """
    canonical = route_template(normalize_url(url, drop_query=True))
    names_set = {(p or "").lower() for p in (param_names or []) if p}
    query = urlsplit(url.strip()).query if url else ""
    for k, _v in parse_qsl(query, keep_blank_values=True):
        if k and k.lower() not in _VOLATILE_PARAMS:
            names_set.add(k.lower())
    names = ",".join(sorted(names_set))
    return f"{method.upper()} {canonical} [{names}]"
