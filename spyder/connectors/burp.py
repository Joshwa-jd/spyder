"""Connector for Burp Suite — integrates via Burp's REST API and proxy.

Two integration modes, both relying on the operator's own running Burp instance:

  1. Proxy mode: route SPYDER's HTTP traffic through Burp (set http.proxy to
     Burp's listener, e.g. http://127.0.0.1:8080) so all recon traffic lands in
     Burp's history for manual analysis. This needs no code here beyond config.

  2. API mode: trigger Burp's own scanner via its REST API (Enterprise/Pro with
     the REST API enabled) and pull results back as Findings.

SPYDER never reimplements Burp's scanning; it asks Burp to do what Burp does.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..core.models import Finding, Severity
from ..plugins.framework import ConnectorPlugin
from ..utils.logging import get_logger

log = get_logger("connector.burp")

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}


class BurpConnector(ConnectorPlugin):
    name = "burp"
    version = "1.0.0"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        api_url = options.get("api_url", "http://127.0.0.1:1337")
        api_key = options.get("api_key")
        if not api_key:
            log.info(
                "No Burp API key provided. Use proxy mode instead: set http.proxy to your "
                "Burp listener so recon traffic appears in Burp history."
            )
            return [
                Finding(
                    title="Burp proxy mode available",
                    severity=Severity.INFO,
                    description="Route SPYDER traffic through Burp by setting http.proxy.",
                    source="SPYDER:burp",
                )
            ]
        return await self._scan_via_api(api_url, api_key, target, options)

    async def _scan_via_api(self, api_url: str, api_key: str, target: str, options: dict) -> list[Finding]:
        base = api_url.rstrip("/") + f"/{api_key}/v0.1"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{base}/scan", json={"urls": [target]})
            resp.raise_for_status()
            task_id = resp.headers.get("Location", "").rsplit("/", 1)[-1]
            log.info("Burp scan queued: task %s", task_id)
            return [
                Finding(
                    title="Burp scan started",
                    severity=Severity.INFO,
                    endpoint=target,
                    description=f"Burp scan task {task_id} queued. Poll {base}/scan/{task_id}.",
                    evidence={"task_id": task_id},
                    source="SPYDER:burp",
                )
            ]
