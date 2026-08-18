"""Regression tests for crawler concurrency correctness and determinism.

These cover invariants that only break under concurrent scheduling, so they use
a stub client with controllable per-URL delays rather than a live server.
"""
from __future__ import annotations

import asyncio
import random

from spyder.core.config import CrawlConfig
from spyder.crawler.engine import Crawler
from spyder.http.client import Transaction
from spyder.utils.scope import ScopeGuard

HOST = "https://target.test"

# A small deterministic site: a fan-out seed, one hop, then leaves.
SITE = {
    f"{HOST}/": '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>',
    f"{HOST}/a": '<a href="/d">d</a>',
    f"{HOST}/b": '<a href="/e">e</a>',
    f"{HOST}/c": '<a href="/f">f</a>',
    f"{HOST}/d": "leaf",
    f"{HOST}/e": "leaf",
    f"{HOST}/f": "leaf",
}

# A wider, two-level site so a max_pages cap can bite *mid-level*, where the
# frontier order used to depend on which parent responded first.
WIDE = {
    f"{HOST}/": "".join(f'<a href="/p{i}">p{i}</a>' for i in range(12)),
    **{f"{HOST}/p{i}": f'<a href="/q{i}">q{i}</a>' for i in range(12)},
    **{f"{HOST}/q{i}": "leaf" for i in range(12)},
}


class StubClient:
    """Minimal HTTPClient stand-in with a controllable per-URL delay."""

    def __init__(self, delays: dict[str, float] | None = None, site: dict[str, str] | None = None):
        self.delays = delays or {}
        self.site = SITE if site is None else site
        self.requested: list[str] = []

    async def get(self, url: str) -> Transaction:
        self.requested.append(url)
        delay = self.delays.get(url, 0.0)
        if delay:
            await asyncio.sleep(delay)
        body = self.site.get(url)
        return Transaction(
            id="stub",
            method="GET",
            url=url,
            request_headers={},
            request_body=None,
            status=200 if body is not None else 404,
            response_headers={"content-type": "text/html"},
            body=body or "",
        )


def _crawler(client: StubClient, **overrides: object) -> Crawler:
    cfg = CrawlConfig(
        respect_robots=False,
        parse_sitemap=False,
        extract_js_endpoints=False,
        **overrides,  # type: ignore[arg-type]
    )
    return Crawler(client, ScopeGuard(["target.test"]), cfg)  # type: ignore[arg-type]


async def test_crawl_is_a_barrier_for_its_own_tasks() -> None:
    """crawl() must not leave any task it spawned alive after it returns.

    Regression: workers were cancelled but never awaited, so a worker suspended
    inside an in-flight request kept using the shared connection pool after
    crawl() returned, corrupting the caller's next response.

    Asserted as a property of crawl() rather than of any particular concurrency
    strategy, so it stays meaningful if the internals change.
    """
    # Slow leaves guarantee fetches are still in flight when the frontier drains.
    client = StubClient(delays={f"{HOST}/d": 0.05, f"{HOST}/e": 0.05})
    crawler = _crawler(client)

    before = asyncio.all_tasks()
    await crawler.crawl(f"{HOST}/")
    leaked = [t for t in asyncio.all_tasks() if t not in before and not t.done()]

    assert leaked == [], f"{len(leaked)} task(s) spawned by crawl() outlived it"


def _latency_profile(seed: int, site: dict[str, str]) -> dict[str, float]:
    """A reproducible but distinct per-URL latency profile."""
    rng = random.Random(seed)
    return {url: rng.choice([0.0, 0.001, 0.003]) for url in site}


async def _crawl_urls(seed: int, site: dict[str, str], **overrides: object) -> list[str]:
    client = StubClient(delays=_latency_profile(seed, site), site=site)
    crawler = _crawler(client, **overrides)
    return [ep.url for ep in await crawler.crawl(f"{HOST}/")]


async def test_endpoint_order_is_independent_of_response_latency() -> None:
    """Endpoint order must be a function of the target, not of network timing.

    Regression: crawl() returned ``list(self.endpoints.values())``, i.e. the
    order concurrent fetches happened to finish in, so repeat scans of an
    unchanged target produced differently-ordered reports.
    """
    runs = [await _crawl_urls(s, WIDE) for s in range(6)]

    assert len({frozenset(r) for r in runs}) == 1, "endpoint set itself varied"
    assert len({tuple(r) for r in runs}) == 1, (
        f"{len({tuple(r) for r in runs})} distinct orderings across 6 runs"
    )


async def test_max_pages_selection_is_independent_of_response_latency() -> None:
    """Which pages survive the max_pages cap must not depend on timing.

    Regression: workers pulled from a shared queue whose contents arrived in
    completion order, so when ``max_pages`` truncated the crawl mid-level the
    surviving page set — and therefore the findings — changed between runs.
    """
    # 1 seed + 12 depth-1 pages = 13, so a cap of 20 truncates *within* depth 2.
    runs = [await _crawl_urls(s, WIDE, max_pages=20) for s in range(8)]

    assert all(len(r) == len(runs[0]) for r in runs), "result sizes varied"
    assert len({frozenset(r) for r in runs}) == 1, (
        f"{len({frozenset(r) for r in runs})} distinct page sets across 8 runs"
    )
