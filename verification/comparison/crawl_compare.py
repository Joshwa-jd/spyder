"""Score SPYDER's crawler against reference crawlers on a known-answer site.

Every tool is run against the same ground-truth server and scored against the
same manifest, so the numbers are absolute (recall against known truth), not
just "SPYDER vs katana". Missing reference tools are reported as skipped rather
than silently dropped.

Usage:  python -m verification.comparison.crawl_compare
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from urllib.parse import urlparse

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

from spyder.core.config import CrawlConfig, HTTPConfig  # noqa: E402
from spyder.crawler.engine import Crawler  # noqa: E402
from spyder.http.client import HTTPClient  # noqa: E402
from spyder.utils.scope import ScopeGuard  # noqa: E402
from verification.groundtruth.server import ground_truth_server  # noqa: E402
from verification.groundtruth.site import (  # noqa: E402
    TRUTH_JS_ONLY,
    TRUTH_LINKED,
    TRUTH_PHANTOM,
    TRUTH_ROBOTS_ONLY,
    TRUTH_SITEMAP_ONLY,
    all_truth_paths,
)

TIMEOUT = 180


def _paths(urls: set[str], base: str) -> set[str]:
    """Reduce absolute URLs to in-scope paths; drop everything off-host."""
    host = urlparse(base).netloc
    out = set()
    for u in urls:
        p = urlparse(u)
        if p.netloc and p.netloc != host:
            continue
        path = p.path.rstrip("/") or "/"
        out.add(path)
    return out


def _offhost(urls: set[str], base: str) -> set[str]:
    host = urlparse(base).netloc
    return {u for u in urls if urlparse(u).netloc and urlparse(u).netloc != host}


async def run_spyder(base: str) -> set[str]:
    cfg = CrawlConfig(max_depth=4, max_pages=200)
    async with HTTPClient(HTTPConfig()) as client:
        crawler = Crawler(client, ScopeGuard([urlparse(base).hostname or ""]), cfg)
        eps = await crawler.crawl(base + "/")
    return {e.url for e in eps}


def _run(cmd: list[str], stdin: str | None = None) -> set[str]:
    """Run a reference crawler. Raises on failure rather than reporting an
    empty result set — a silent 0 would misrepresent a broken harness as a
    reference tool that found nothing."""
    try:
        proc = subprocess.run(
            cmd, input=stdin, capture_output=True, text=True, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} exceeded {TIMEOUT}s — result would be misleading") from None
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd[0]} exited {proc.returncode}: {proc.stderr[:300]}")
    return {ln.strip() for ln in proc.stdout.splitlines() if ln.strip().startswith("http")}


def run_katana(base: str) -> set[str]:
    return _run(["katana", "-u", base + "/", "-d", "4", "-jc", "-silent"])


def run_hakrawler(base: str) -> set[str]:
    return _run(["hakrawler", "-d", "3", "-u"], stdin=base + "/\n")


def score(name: str, found: set[str], base: str) -> dict[str, object]:
    paths = _paths(found, base)
    truth = all_truth_paths()
    hit = paths & truth
    return {
        "tool": name,
        "found": len(paths),
        "recall": f"{len(hit)}/{len(truth)}",
        "pct": round(100 * len(hit) / len(truth)),
        "linked": len(paths & TRUTH_LINKED),
        "robots": len(paths & TRUTH_ROBOTS_ONLY),
        "sitemap": len(paths & TRUTH_SITEMAP_ONLY),
        "js": len(paths & TRUTH_JS_ONLY),
        "offhost": len(_offhost(found, base)),
        "phantom": sorted(paths & TRUTH_PHANTOM),
        "missing": sorted(truth - paths),
    }


def main() -> int:
    with ground_truth_server() as base:
        results = [score("SPYDER", asyncio.run(run_spyder(base)), base)]
        for name, fn in (("katana", run_katana), ("hakrawler", run_hakrawler)):
            if not shutil.which(name):
                print(f"[skip] {name} not installed")
                continue
            try:
                results.append(score(name, fn(base), base))
            except RuntimeError as exc:
                print(f"[fail] {name}: {exc}")

    truth = all_truth_paths()
    print(f"\nGround truth: {len(truth)} discoverable paths "
          f"(linked {len(TRUTH_LINKED)}, robots {len(TRUTH_ROBOTS_ONLY)}, "
          f"sitemap {len(TRUTH_SITEMAP_ONLY)}, js {len(TRUTH_JS_ONLY)})\n")
    hdr = f"{'tool':10} {'recall':>8} {'%':>4} {'link':>5} {'robot':>6} {'map':>4} {'js':>3} {'offhost':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        print(f"{r['tool']:10} {r['recall']:>8} {r['pct']:>4} {r['linked']:>5} "
              f"{r['robots']:>6} {r['sitemap']:>4} {r['js']:>3} {r['offhost']:>8}")
    print()
    for r in results:
        if r["missing"]:
            print(f"{r['tool']} missed: {', '.join(r['missing'])}")  # type: ignore[arg-type]
        if r["phantom"]:
            print(f"{r['tool']} FALSE POSITIVE (phantom URL): {', '.join(r['phantom'])}")  # type: ignore[arg-type]
        if r["offhost"]:
            print(f"{r['tool']} SCOPE VIOLATION: {r['offhost']} off-host URL(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
