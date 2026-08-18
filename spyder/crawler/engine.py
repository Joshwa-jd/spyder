"""Async crawler & discovery engine.

Discovers endpoints, forms, parameters, sitemap entries, and JS-referenced URLs
within an enforced scope. Read-only: it fetches and parses, never submits forms.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.config import CrawlConfig
from ..core.events import EventBus, EventType
from ..core.models import Endpoint, HTTPMethod, Parameter, ParamLocation
from ..http.client import HTTPClient
from ..utils.logging import get_logger
from ..utils.scope import ScopeGuard

log = get_logger("crawler")

# Heuristic extraction of URL-ish strings from inline/served JavaScript.
_JS_URL_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-/.]+(?:\?[^"'`]*)?)["'`]""")
_ROBOTS_RE = re.compile(r"(?:Allow|Disallow):\s*(\S+)", re.I)


def _attr(el: object, name: str) -> str | None:
    """Read a single string HTML attribute value.

    BeautifulSoup returns ``str`` for normal attributes but a list for
    multi-valued ones (e.g. ``class``); collapse both to a single string so
    callers always get ``str | None``.
    """
    val = el.get(name) if hasattr(el, "get") else None  # type: ignore[attr-defined]
    if isinstance(val, list):
        val = val[0] if val else None
    return val if isinstance(val, str) else None


class Crawler:
    def __init__(
        self,
        client: HTTPClient,
        scope: ScopeGuard,
        config: CrawlConfig,
        events: EventBus | None = None,
    ):
        self.client = client
        self.scope = scope
        self.config = config
        self.events = events
        self.endpoints: dict[str, Endpoint] = {}
        self._seen: set[str] = set()

    def _add_endpoint(self, ep: Endpoint) -> None:
        fp = ep.fingerprint()
        if fp not in self.endpoints:
            self.endpoints[fp] = ep
            if self.events:
                self.events.emit(
                    EventType.ENDPOINT_FOUND,
                    f"{ep.method.value} {ep.url}",
                    source="crawler",
                    url=ep.url,
                    method=ep.method.value,
                    via=ep.discovered_via,
                )

    @staticmethod
    def _query_params(url: str) -> list[Parameter]:
        qs = parse_qs(urlparse(url).query)
        return [
            Parameter(name=k, location=ParamLocation.QUERY, example=v[0] if v else None)
            for k, v in qs.items()
        ]

    def _extract_links(self, base_url: str, html: str) -> set[str]:
        soup = BeautifulSoup(html, "html.parser")
        links: set[str] = set()
        for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"), ("form", "action")):
            for el in soup.find_all(tag):
                val = _attr(el, attr)
                if val:
                    links.add(urljoin(base_url, val))
        # forms -> endpoints with body params
        for form in soup.find_all("form"):
            action = urljoin(base_url, _attr(form, "action") or base_url)
            method = (_attr(form, "method") or "GET").upper()
            params = [
                Parameter(
                    name=name,
                    location=ParamLocation.BODY if method == "POST" else ParamLocation.QUERY,
                    source="form",
                )
                for inp in form.find_all(["input", "textarea", "select"])
                if (name := _attr(inp, "name"))
            ]
            if action and self.scope.in_scope(action):
                self._add_endpoint(
                    Endpoint(
                        url=action,
                        method=HTTPMethod(method) if method in HTTPMethod._value2member_map_ else HTTPMethod.GET,
                        params=params,
                        discovered_via="form",
                    )
                )
        if self.config.extract_js_endpoints:
            for m in _JS_URL_RE.finditer(html):
                links.add(urljoin(base_url, m.group(1)))
        return links

    async def _fetch_robots_and_sitemap(self, base_url: str) -> set[str]:
        found: set[str] = set()
        root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        if self.config.respect_robots:
            txn = await self.client.get(urljoin(root, "/robots.txt"))
            if txn.status == 200:
                for m in _ROBOTS_RE.finditer(txn.body):
                    found.add(urljoin(root, m.group(1)))
        if self.config.parse_sitemap:
            txn = await self.client.get(urljoin(root, "/sitemap.xml"))
            if txn.status == 200:
                found.update(re.findall(r"<loc>([^<]+)</loc>", txn.body))
        return {u for u in found if self.scope.in_scope(u)}

    async def _fetch_one(self, url: str) -> set[str]:
        """Fetch one page, record its endpoint, and return its in-scope links."""
        txn = await self.client.get(url)
        ctype_hdr = txn.response_headers.get("content-type")
        self._add_endpoint(
            Endpoint(
                url=url,
                params=self._query_params(url),
                status=txn.status,
                content_type=ctype_hdr,
            )
        )
        # The body belongs to the *final* URL after redirects. Resolving its
        # links against the requested URL invents endpoints that do not exist
        # (e.g. /legacy -> /docs/guide/ turned a relative "intro" into "/intro").
        base = txn.final_url or url
        if base != url and self.scope.in_scope(base):
            self._seen.add(base)
            self._add_endpoint(
                Endpoint(
                    url=base,
                    params=self._query_params(base),
                    status=txn.status,
                    content_type=ctype_hdr,
                    discovered_via="redirect",
                )
            )
        if self.events:
            self.events.emit(
                EventType.CRAWL_PROGRESS,
                f"crawled {len(self._seen)} pages · {len(self.endpoints)} endpoints",
                source="crawler",
                pages=len(self._seen),
                endpoints=len(self.endpoints),
            )
        ctype = (ctype_hdr or "").lower()
        if "html" not in ctype and "javascript" not in ctype:
            return set()
        return {u for u in self._extract_links(base, txn.body) if self.scope.in_scope(u)}

    async def crawl(self, seed_url: str) -> list[Endpoint]:
        """Crawl breadth-first, one depth level at a time.

        Levels are walked synchronously and each level's URLs are *selected*
        (sorted, deduped, and charged against ``max_pages``) before any request
        is issued. A free-running worker pool instead let response latency decide
        both which pages survived the ``max_pages`` cap and what order endpoints
        came back in, so the same target yielded different results run to run.
        Fetches within a level still run concurrently, bounded by ``concurrency``.
        """
        log.info("crawl start %s (depth=%d, max=%d)", seed_url, self.config.max_depth, self.config.max_pages)
        extra = await self._fetch_robots_and_sitemap(seed_url)
        level: set[str] = {seed_url}
        sem = asyncio.Semaphore(max(1, self.config.concurrency))

        async def _guarded(u: str) -> set[str]:
            async with sem:
                return await self._fetch_one(u)

        for depth in range(self.config.max_depth + 1):
            if depth == 1:
                level |= extra
            # Deterministic selection: sorted, and charged against the page
            # budget before any I/O, so latency cannot influence the outcome.
            batch: list[str] = []
            for url in sorted(level):
                if len(self._seen) >= self.config.max_pages:
                    break
                if url in self._seen or not self.scope.in_scope(url):
                    continue
                self._seen.add(url)
                batch.append(url)
            if not batch:
                if depth >= 1 or not extra:
                    break
                level = set()
                continue
            results = await asyncio.gather(*(_guarded(u) for u in batch), return_exceptions=True)
            level = set()
            for url, res in zip(batch, results, strict=True):
                if isinstance(res, BaseException):
                    log.debug("crawl error on %s: %s", url, res)
                    continue
                level |= res
            level -= self._seen

        log.info("crawl done: %d endpoints from %d pages", len(self.endpoints), len(self._seen))
        # Sorted so the endpoint list is a function of the target, not of the
        # order concurrent fetches happened to complete in.
        return [self.endpoints[k] for k in sorted(self.endpoints)]
