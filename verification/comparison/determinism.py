"""Repeat-scan determinism and crawl throughput against the ground-truth server.

The server is deterministic by construction, so any variation across runs is the
crawler's. Output is hashed rather than eyeballed: N runs must collapse to one
digest, covering endpoint set, order, status, and parameters.

Usage:  python -m verification.comparison.determinism [runs]
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from spyder.core.config import CrawlConfig, HTTPConfig  # noqa: E402
from spyder.crawler.engine import Crawler  # noqa: E402
from spyder.http.client import HTTPClient  # noqa: E402
from spyder.utils.scope import ScopeGuard  # noqa: E402
from verification.groundtruth.server import ground_truth_server  # noqa: E402


def _digest(endpoints: list[object]) -> str:
    """Hash the full observable result, not just the URL set."""
    payload = [
        {
            "url": e.url,  # type: ignore[attr-defined]
            "method": e.method.value,  # type: ignore[attr-defined]
            "status": e.status,  # type: ignore[attr-defined]
            "via": e.discovered_via,  # type: ignore[attr-defined]
            "params": sorted(p.name for p in e.params),  # type: ignore[attr-defined]
        }
        for e in endpoints
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=False).encode()).hexdigest()


async def one_run(base: str, cap: int) -> tuple[str, float, int]:
    cfg = CrawlConfig(max_depth=4, max_pages=cap)
    started = time.perf_counter()
    async with HTTPClient(HTTPConfig()) as client:
        crawler = Crawler(client, ScopeGuard([urlparse(base).hostname or ""]), cfg)
        eps = await crawler.crawl(base + "/")
    return _digest(eps), (time.perf_counter() - started) * 1000, len(eps)


def main() -> int:
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    # An uncapped pass, plus one whose page budget truncates the crawl mid-level
    # — the case where selection order used to decide the outcome.
    scenarios = {"uncapped": 200, "capped(max_pages=12)": 12}

    failures = 0
    with ground_truth_server() as base:
        for label, cap in scenarios.items():
            digests, times, counts = [], [], []
            for _ in range(runs):
                d, ms, n = asyncio.run(one_run(base, cap))
                digests.append(d)
                times.append(ms)
                counts.append(n)
            unique = sorted(set(digests))
            ok = len(unique) == 1
            failures += 0 if ok else 1
            print(f"\n{label}: {runs} runs")
            print(f"  distinct results : {len(unique)}  {'OK' if ok else 'NONDETERMINISTIC'}")
            print(f"  endpoints        : {sorted(set(counts))}")
            print(f"  digest           : {unique[0][:16]}"
                  + ("" if ok else f"  (+{len(unique) - 1} others)"))
            print(f"  crawl ms         : min {min(times):.0f} / "
                  f"median {statistics.median(times):.0f} / max {max(times):.0f}")
            if not ok:
                for d in unique:
                    print(f"    {d[:16]} x{digests.count(d)}")

    print(f"\n{'PASS' if not failures else 'FAIL'}: "
          f"{len(scenarios) - failures}/{len(scenarios)} scenarios deterministic over {runs} runs")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
