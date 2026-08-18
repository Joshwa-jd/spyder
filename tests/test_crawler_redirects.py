"""Redirect handling, verified against the ground-truth server over real HTTP.

A stub client cannot exercise this: the defect lives in the gap between the URL
requested and the URL the response actually came from, which only httpx's
redirect following produces.
"""
from __future__ import annotations

from urllib.parse import urlparse

from spyder.core.config import CrawlConfig, HTTPConfig
from spyder.crawler.engine import Crawler
from spyder.http.client import HTTPClient
from spyder.utils.scope import ScopeGuard
from verification.groundtruth.server import ground_truth_server


async def _crawl_paths() -> set[str]:
    with ground_truth_server() as base:
        cfg = CrawlConfig(max_depth=4, max_pages=200)
        async with HTTPClient(HTTPConfig()) as client:
            crawler = Crawler(client, ScopeGuard([urlparse(base).hostname or ""]), cfg)
            eps = await crawler.crawl(base + "/")
        return {urlparse(e.url).path.rstrip("/") or "/" for e in eps}


async def test_relative_links_resolve_against_the_post_redirect_url() -> None:
    """/legacy redirects to /docs/guide/, whose relative link is "intro".

    Regression: links were resolved against the *requested* URL, so "intro"
    became "/intro" — an endpoint that does not exist anywhere on the site.
    """
    paths = await _crawl_paths()

    assert "/intro" not in paths, "invented /intro by resolving against the pre-redirect URL"
    assert "/docs/guide/intro" in paths


async def test_redirect_targets_are_recorded_as_endpoints() -> None:
    """A redirect's destination is a discovered endpoint in its own right."""
    paths = await _crawl_paths()

    assert "/old-page" in paths, "the redirecting URL itself should still be recorded"
    assert "/new-page" in paths
    assert "/docs/guide" in paths
