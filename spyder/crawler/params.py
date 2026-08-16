"""Parameter discovery & reflection analysis.

Sends benign, unique marker tokens (not attack payloads) to observe whether and
where input is reflected. This is reconnaissance: it maps the attack surface so a
human analyst knows where to look. It does not inject exploitation payloads.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..analysis.diff import find_reflections
from ..core.models import Endpoint, Parameter, ParamLocation
from ..http.client import HTTPClient
from ..utils.logging import get_logger

log = get_logger("params")


@dataclass
class ReflectionResult:
    endpoint: str
    param: str
    location: str
    reflected: bool


def _marker() -> str:
    # Alphanumeric, harmless, unlikely to collide or be filtered as malicious.
    return "spyder" + uuid.uuid4().hex[:10]


class ParameterProber:
    """Probes known parameters with benign markers to detect reflection points."""

    def __init__(self, client: HTTPClient):
        self.client = client

    async def probe(self, endpoint: Endpoint) -> list[ReflectionResult]:
        results: list[ReflectionResult] = []
        for param in endpoint.params:
            marker = _marker()
            txn = await self._send(endpoint, param, marker)
            reflected = find_reflections(marker, txn.body) if txn else False
            param.reflected = reflected
            results.append(
                ReflectionResult(endpoint.url, param.name, param.location.value, reflected)
            )
            if reflected:
                log.debug("reflection: %s param=%s", endpoint.url, param.name)
        return results

    async def _send(self, endpoint: Endpoint, param: Parameter, marker: str):
        loc = param.location
        if loc == ParamLocation.QUERY:
            return await self.client.get(endpoint.url, params={param.name: marker})
        if loc == ParamLocation.BODY:
            return await self.client.request(
                endpoint.method.value, endpoint.url, data={param.name: marker}
            )
        if loc == ParamLocation.JSON:
            return await self.client.request(
                endpoint.method.value, endpoint.url, json={param.name: marker}
            )
        if loc == ParamLocation.HEADER:
            return await self.client.get(endpoint.url, headers={param.name: marker})
        if loc == ParamLocation.COOKIE:
            return await self.client.get(endpoint.url, headers={"Cookie": f"{param.name}={marker}"})
        return await self.client.get(endpoint.url)
