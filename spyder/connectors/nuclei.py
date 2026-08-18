"""Connector for nuclei — orchestrates the user's installed nuclei binary.

nuclei runs community/templated checks the operator selects. SPYDER builds the
command, runs it against an authorized target, and parses JSONL output into
Findings. SPYDER does not ship templates or exploitation logic of its own.
"""
from __future__ import annotations

import json
from typing import Any

from ..core.models import Finding, Severity
from .base import ExternalToolConnector

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiConnector(ExternalToolConnector):
    name = "nuclei"
    version = "1.0.0"
    binary = "nuclei"

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        args = ["-u", target, "-jsonl", "-silent"]
        if templates := options.get("templates"):
            args += ["-t", templates]
        if tags := options.get("tags"):
            args += ["-tags", tags]
        if severity := options.get("severity"):
            args += ["-severity", severity]
        if rate := options.get("rate_limit"):
            args += ["-rate-limit", str(rate)]
        result = await self._exec(args, timeout=options.get("timeout", 900.0))
        return self._parse(result.stdout)

    def _parse(self, stdout: str) -> list:
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            sev = _SEV_MAP.get((info.get("severity") or "info").lower(), Severity.INFO)
            findings.append(
                self._finding(
                    title=info.get("name", obj.get("template-id", "nuclei finding")),
                    severity=sev,
                    endpoint=obj.get("matched-at") or obj.get("host"),
                    description=info.get("description", ""),
                    evidence={
                        "template": obj.get("template-id"),
                        "type": obj.get("type"),
                        "matched": obj.get("matched-at"),
                    },
                    cwe=[c.upper() for c in info.get("classification", {}).get("cwe-id", []) or []],
                    remediation=info.get("remediation", ""),
                )
            )
        return findings
