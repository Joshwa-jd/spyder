"""Base class for external-tool connectors.

Connectors orchestrate *existing, user-installed* analyst tools as subprocesses.
SPYDER does not reimplement their logic; it builds command lines, runs them under
the operator's authority, captures output, and normalizes results into Findings.

Design principles:
  * The external binary must already be installed and on PATH.
  * SPYDER never bundles exploitation logic — it shells out to the tool the
    analyst already chose to use against an authorized target.
  * Every invocation is logged and surfaced so the operator sees exactly what ran.
"""
from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable
from dataclasses import dataclass

from ..core.events import EventBus, EventType
from ..core.models import Finding
from ..plugins.framework import ConnectorError, ConnectorPlugin, ConnectorValidation
from ..utils.logging import get_logger

log = get_logger("connectors")

# ``ConnectorError`` now lives in the plugin layer so a single class is shared
# by the framework, this base, and every connector. Re-exported here for the
# many ``from .base import ConnectorError`` call sites that predate the move.
__all__ = ["ConnectorError", "ExternalToolConnector", "ProcResult"]


@dataclass
class ProcResult:
    returncode: int
    stdout: str
    stderr: str


class ExternalToolConnector(ConnectorPlugin):
    """Common subprocess plumbing for tool connectors."""

    binary: str = ""
    # Optional event bus, injected by the orchestrator before run() for live streaming.
    events: EventBus | None = None

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def _require_binary(self) -> None:
        if not self.available():
            raise ConnectorError(
                f"'{self.binary}' not found on PATH. Install it and ensure it is runnable."
            )

    def validate(
        self, target: str, options: dict | None = None
    ) -> ConnectorValidation:
        """Subprocess pre-flight: a target and an installed binary are required."""
        errors: list[str] = []
        if not (target or "").strip():
            errors.append("no target provided")
        if not self.available():
            errors.append(f"'{self.binary}' not found on PATH")
        return ConnectorValidation.failure(*errors) if errors else ConnectorValidation.success()

    def status(self) -> dict:
        st = super().status()
        st["binary"] = self.binary
        st["path"] = shutil.which(self.binary) if self.binary else None
        return st

    def _emit(self, type: EventType, message: str, **data) -> None:
        if self.events:
            self.events.emit(type, message, source=self.name, **data)

    async def _exec(self, args: list[str], timeout: float = 600.0) -> ProcResult:
        self._require_binary()
        log.info("exec: %s %s", self.binary, " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError as exc:
            proc.kill()
            raise ConnectorError(f"{self.binary} timed out after {timeout}s") from exc
        return ProcResult(proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace"))

    async def _stream(
        self,
        args: list[str],
        on_line: Callable[[str], None],
        timeout: float = 900.0,
        input_data: str | None = None,
    ) -> int:
        """Run the tool, invoking ``on_line`` for each stdout line as it arrives.

        Optionally feeds ``input_data`` to stdin (for tools like waybackurls that
        read a target from stdin). Returns the process exit code. Lets recon tools
        surface discoveries live through the event bus rather than only at the end.
        """
        self._require_binary()
        log.info("stream: %s %s", self.binary, " ".join(args))
        proc = await asyncio.create_subprocess_exec(
            self.binary,
            *args,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if input_data is not None and proc.stdin is not None:
            proc.stdin.write(input_data.encode())
            await proc.stdin.drain()
            proc.stdin.close()

        async def _pump() -> None:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").strip()
                if line:
                    on_line(line)

        try:
            await asyncio.wait_for(_pump(), timeout=timeout)
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError as exc:
            proc.kill()
            raise ConnectorError(f"{self.binary} timed out after {timeout}s") from exc
        return proc.returncode or 0

    def _finding(self, **kw) -> Finding:
        kw.setdefault("source", f"SPYDER:{self.name}")
        return Finding(**kw)
