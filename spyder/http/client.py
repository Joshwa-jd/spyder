"""Proxy-aware async HTTP client with retries, rate limiting, and replayable records."""
from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..core.config import HTTPConfig, _default_user_agent
from ..utils.logging import get_logger
from ..utils.scope import RateLimiter

log = get_logger("http")


@dataclass
class Transaction:
    """A recorded request/response pair — the unit of replay and diffing."""

    id: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None
    status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None
    #: URL the response actually came from. Differs from ``url`` when redirects
    #: were followed; ``None`` if the request never completed. Callers resolving
    #: relative links MUST use this, not ``url``.
    final_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "status": self.status,
            "response_headers": self.response_headers,
            "body_len": len(self.body),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
        }


class HTTPClient:
    """Wraps httpx.AsyncClient with SPYDER concerns: UA rotation, rate limit, recording."""

    def __init__(self, config: HTTPConfig, rate_per_sec: float = 10.0, record: bool = True):
        self.config = config
        self.record = record
        self.transactions: list[Transaction] = []
        self._ua_cycle = itertools.cycle(config.user_agents or [_default_user_agent()])
        self._limiter = RateLimiter(rate_per_sec)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HTTPClient:
        self._client = httpx.AsyncClient(
            http2=self.config.http2,
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
            follow_redirects=self.config.follow_redirects,
            proxy=self.config.proxy,
            limits=httpx.Limits(max_connections=self.config.max_connections),
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client:
            await self._client.aclose()

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers = dict(self.config.default_headers)
        headers["User-Agent"] = next(self._ua_cycle)
        if extra:
            headers.update(extra)
        return headers

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
    ) -> Transaction:
        assert self._client is not None, "Use HTTPClient as an async context manager"
        hdrs = self._headers(headers)
        txn = Transaction(
            id=str(uuid.uuid4())[:8],
            method=method.upper(),
            url=url,
            request_headers=hdrs,
            request_body=str(data or json) if (data or json) else None,
        )
        attempt = 0
        start = time.monotonic()
        while True:
            # Charged per *attempt*, not per call: the retry loop is inside this
            # method, so acquiring once above let a single token pay for
            # ``max_retries + 1`` connections. Against a target that had begun
            # refusing traffic — precisely when a scanner should ease off — an
            # agreed 5 req/s was measured at 28 conn/s. The rate limit is the
            # operator's contract with the target's owner, and every packet on
            # the wire falls under it. Pacing retries this way also gives the
            # retry path the backoff it otherwise had none of.
            await self._limiter.acquire()
            try:
                resp = await self._client.request(
                    method, url, headers=hdrs, params=params, data=data, json=json
                )
                txn.status = resp.status_code
                txn.response_headers = dict(resp.headers)
                txn.body = resp.text
                txn.final_url = str(resp.url)
                txn.elapsed_ms = (time.monotonic() - start) * 1000
                break
            except httpx.HTTPError as exc:
                attempt += 1
                if attempt > self.config.max_retries:
                    txn.error = f"{type(exc).__name__}: {exc}"
                    txn.elapsed_ms = (time.monotonic() - start) * 1000
                    log.debug("request failed %s %s: %s", method, url, exc)
                    break
        if self.record:
            self.transactions.append(txn)
        return txn

    async def get(self, url: str, **kw: Any) -> Transaction:
        return await self.request("GET", url, **kw)

    async def replay(self, txn: Transaction) -> Transaction:
        """Re-issue a recorded transaction exactly — the analyst replay primitive."""
        return await self.request(
            txn.method,
            txn.url,
            headers=txn.request_headers,
            data=txn.request_body,
        )
