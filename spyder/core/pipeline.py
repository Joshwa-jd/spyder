"""The unified command pipeline (Phase 3).

Every operator command flows through the same ordered stages:

    parse → validate → permission → workspace → execute → plugins → result → db → render

Those stages are already implemented inside :class:`~spyder.core.orchestrator.Orchestrator`;
this module gives them a single named, importable identity so the lifecycle is
discoverable and can be reasoned about as a first-class concept rather than being
implicit in the orchestrator's method bodies.

:class:`CommandPipeline` is a thin facade over an existing ``Orchestrator`` — it
deliberately does not re-implement recon, analysis, persistence, or rendering.
It exists to name the flow and to be the single documented entry the CLI and
dashboard drive, so both share exactly one execution path.
"""
from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import Endpoint, Finding, Target
    from .orchestrator import Orchestrator


class PipelineStage(StrEnum):
    """The canonical, ordered stages every command passes through."""

    PARSE = "parse"
    VALIDATE = "validate"
    PERMISSION = "permission"
    WORKSPACE = "workspace"
    EXECUTE = "execute"
    PLUGINS = "plugins"
    RESULT = "result"
    DATABASE = "database"
    RENDER = "render"

    @classmethod
    def ordered(cls) -> list[PipelineStage]:
        return [
            cls.PARSE, cls.VALIDATE, cls.PERMISSION, cls.WORKSPACE,
            cls.EXECUTE, cls.PLUGINS, cls.RESULT, cls.DATABASE, cls.RENDER,
        ]


class CommandPipeline:
    """Single, named entry point for running commands through the shared lifecycle.

    Wraps an :class:`Orchestrator`. The orchestrator owns the per-stage work
    (crawl, analyzers, connector lifecycle, workspace persistence, event
    emission); the pipeline names the flow and is what callers drive so the CLI
    and the dashboard cannot drift onto divergent execution paths.
    """

    def __init__(self, orchestrator: Orchestrator) -> None:
        self.orchestrator = orchestrator

    @property
    def stages(self) -> list[PipelineStage]:
        return PipelineStage.ordered()

    async def run_scan(self, target: Target) -> list[Finding]:
        """Recon + analyzers: the `scan` command's full lifecycle.

        Returns every finding the scan produced, which is more than the
        analyzers' own output: ``recon`` persists findings of its own (passive
        fingerprint, version disclosure, secrets seen in JavaScript). Returning
        only ``run_analyzers``' result reported 0 findings for a scan that had
        in fact recorded several, disagreeing with the two paths this facade
        exists to unify — both the CLI and the dashboard print
        ``orch.findings()``. The workspace is the authority on what a scan
        found, so it is what this returns.
        """
        endpoints = await self.orchestrator.recon(target)
        await self.orchestrator.run_analyzers(endpoints)
        return self.orchestrator.findings()

    async def run_crawl(self, target: Target) -> list[Endpoint]:
        """Discovery only: the `crawl` command's lifecycle."""
        return await self.orchestrator.recon(target)

    async def run_connector(
        self, name: str, target: str, options: dict[str, Any]
    ) -> list[Finding]:
        """Drive an external-tool connector through its full lifecycle."""
        return await self.orchestrator.run_connector(name, target, options)
