"""Connector for sqlmap — orchestrates the user's installed sqlmap binary.

This connector does NOT contain SQL injection logic. It shells out to sqlmap,
the established open-source tool the analyst has chosen to run against a target
they are authorized to test. SPYDER's role is orchestration and result capture.

Safety posture:
  * Requires an explicit `authorized=True` flag per invocation; refuses otherwise.
  * Defaults to sqlmap's non-destructive detection flags. Data-extraction or OS
    interaction flags must be supplied deliberately by the operator via `extra_args`
    — SPYDER will not add them on its own.
  * Every command line is logged verbatim.
"""
from __future__ import annotations

from typing import Any

from ..core.models import Severity
from .base import ConnectorError, ExternalToolConnector


class SqlmapConnector(ExternalToolConnector):
    name = "sqlmap"
    version = "1.0.0"
    binary = "sqlmap"

    async def run(self, target: str, options: dict[str, Any]) -> list:  # type: ignore[name-defined]
        if not options.get("authorized"):
            raise ConnectorError(
                "Refusing to run sqlmap without explicit authorization. "
                "Pass authorized=True to confirm you are permitted to test this target."
            )
        # Non-interactive, detection-oriented defaults. The operator opts into more.
        args = ["-u", target, "--batch"]
        if level := options.get("level"):
            args += ["--level", str(level)]
        if risk := options.get("risk"):
            args += ["--risk", str(risk)]
        if data := options.get("data"):
            args += ["--data", data]
        if cookie := options.get("cookie"):
            args += ["--cookie", cookie]
        if proxy := options.get("proxy"):
            args += ["--proxy", proxy]
        # extra_args is the operator's deliberate escape hatch; passed through as-is.
        args += list(options.get("extra_args", []))
        result = await self._exec(args, timeout=options.get("timeout", 1200.0))
        return self._parse(target, result.stdout)

    def _parse(self, target: str, stdout: str) -> list:
        findings = []
        low = stdout.lower()
        if "is vulnerable" in low or "sqlmap identified the following injection point" in low:
            findings.append(
                self._finding(
                    title="sqlmap reported an injection point",
                    severity=Severity.HIGH,
                    endpoint=target,
                    description="sqlmap indicated a parameter appears injectable. "
                    "Confirm manually and capture evidence before reporting.",
                    evidence={"tool_output_tail": stdout[-2000:]},
                    cwe=["CWE-89"],
                    owasp=["A03:2021-Injection"],
                    remediation="Use parameterized queries / prepared statements; "
                    "validate and least-privilege the DB account.",
                )
            )
        elif "all tested parameters do not appear to be injectable" in low:
            findings.append(
                self._finding(
                    title="sqlmap found no injectable parameters",
                    severity=Severity.INFO,
                    endpoint=target,
                    description="sqlmap completed without identifying injection points.",
                )
            )
        return findings
