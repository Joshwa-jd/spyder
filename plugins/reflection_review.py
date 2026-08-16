"""Example SPYDER plugin: flags endpoints whose reflected params warrant review.

Drop this file in a plugin directory (configured via plugin_dirs) and SPYDER will
auto-load it. This demonstrates the AnalyzerPlugin contract. It is purely
observational — it highlights reflection points for a human to investigate.
"""
from __future__ import annotations

from typing import Any

from spyder.core.models import Endpoint, Finding, Severity
from spyder.plugins.framework import AnalyzerPlugin


class ReflectionReviewAnalyzer(AnalyzerPlugin):
    name = "reflection-review"
    version = "1.0.0"

    async def analyze(self, endpoints: list[Endpoint], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for ep in endpoints:
            reflected = [p.name for p in ep.params if p.reflected]
            if reflected:
                findings.append(
                    Finding(
                        title="Reflected parameters present",
                        severity=Severity.LOW,
                        endpoint=ep.url,
                        description=(
                            "Input was reflected in the response for parameters: "
                            + ", ".join(reflected)
                            + ". Review manually for output-encoding / XSS context."
                        ),
                        evidence={"reflected_params": reflected},
                        cwe=["CWE-79"],
                        owasp=["A03:2021-Injection"],
                        remediation="Apply context-aware output encoding; validate input.",
                        source="SPYDER:plugin:reflection-review",
                    )
                )
        return findings
