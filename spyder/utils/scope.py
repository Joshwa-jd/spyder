"""Scope enforcement and async rate limiting."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse


class ScopeGuard:
    """Decides whether a URL is in scope. Defaults to deny when no scope is set."""

    def __init__(self, hosts: list[str], include_subdomains: bool = True):
        self.hosts = {h.lower().lstrip(".") for h in hosts}
        self.include_subdomains = include_subdomains

    def in_scope(self, url: str) -> bool:
        host = urlparse(url).netloc.split(":")[0].lower()
        if not host:
            return False
        if host in self.hosts:
            return True
        if self.include_subdomains:
            return any(host.endswith("." + h) for h in self.hosts)
        return False

    def filter(self, urls: list[str]) -> list[str]:
        return [u for u in urls if self.in_scope(u)]


class RateLimiter:
    """Simple async token-bucket rate limiter."""

    def __init__(self, rate_per_sec: float, burst: int | None = None):
        self.rate = max(rate_per_sec, 0.1)
        self.capacity = burst or max(int(rate_per_sec), 1)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                # Charge the clock for the time spent waiting. Leaving ``_last``
                # at its pre-sleep value credited that interval a second time,
                # as regeneration for the next caller: the waiter paid for a
                # token and then handed the same elapsed time to its successor,
                # so every other request passed free and the bucket sustained
                # exactly twice the configured rate. An operator who agreed 10
                # req/s with a target's owner was sending 20.
                self._last = time.monotonic()
                self._tokens = 0
            else:
                self._tokens -= 1
