"""Tests for the spyder.cli facade and the named command pipeline.

The cli package must front the *single* real implementation of each concern (no
copies), and CommandPipeline must delegate to the orchestrator without adding a
divergent execution path.
"""
from __future__ import annotations

import spyder.__main__ as entry
import spyder.core.models as models
import spyder.ui.banner as ui_banner
import spyder.ui.display as ui_display
import spyder.ui.shell as ui_shell
import spyder.ui.theme as ui_theme
from spyder.core.pipeline import CommandPipeline, PipelineStage


def test_cli_facade_points_at_single_implementations():
    from spyder import cli
    from spyder.cli import (
        banner,
        completion,
        dispatcher,
        parser,
        progress,
        renderer,
        shell,
        validator,
    )

    # Each re-export IS the underlying object, not a copy.
    assert banner.render_banner is ui_banner.render_banner
    assert cli.render_banner is ui_banner.render_banner
    assert dispatcher.main is entry.main
    assert cli.main is entry.main
    assert parser.build_parser is entry.build_parser
    assert shell.run_console is ui_shell.run_console
    assert completion.build_completer is ui_shell._completer
    assert renderer.findings_table is ui_display.findings_table
    assert validator.parse_target is models.parse_target
    assert progress.ok is ui_theme.ok
    assert progress.err is ui_theme.err


def test_pipeline_stage_order_is_the_documented_lifecycle():
    assert [s.value for s in PipelineStage.ordered()] == [
        "parse", "validate", "permission", "workspace",
        "execute", "plugins", "result", "database", "render",
    ]


class _FakeOrchestrator:
    """Records which orchestrator methods the pipeline drives.

    Models the real orchestrator's split: ``recon`` persists findings of its own
    (passive fingerprint, version disclosure) before any analyzer runs, so the
    workspace holds strictly more than ``run_analyzers`` returns.
    """

    def __init__(self):
        self.calls: list[str] = []
        self._workspace: list[str] = []

    async def recon(self, target):
        self.calls.append("recon")
        self._workspace.append("recon-finding")
        return ["ep"]

    async def run_analyzers(self, endpoints):
        self.calls.append("run_analyzers")
        self._workspace.append("finding")
        return ["finding"]

    async def run_connector(self, name, target, options):
        self.calls.append(f"run_connector:{name}")
        return ["cfinding"]

    def findings(self):
        return list(self._workspace)


async def test_pipeline_scan_delegates_to_orchestrator():
    orch = _FakeOrchestrator()
    pipe = CommandPipeline(orch)
    result = await pipe.run_scan(target=object())
    assert result == ["recon-finding", "finding"]
    assert orch.calls == ["recon", "run_analyzers"]


async def test_pipeline_scan_returns_findings_recon_itself_recorded():
    """run_scan must not under-report findings that recon persisted.

    Returning only ``run_analyzers``' output reported 0 findings for a scan that
    had recorded several — SPYDER registers no analyzer plugins by default, so
    the analyzer list is empty on a stock install and every finding a scan
    produces comes from recon. Both the CLI and the dashboard print
    ``orch.findings()``; this named entry point has to agree with them.
    """
    orch = _FakeOrchestrator()
    pipe = CommandPipeline(orch)
    result = await pipe.run_scan(target=object())
    assert "recon-finding" in result, "recon's own findings were dropped"
    assert result == orch.findings()


async def test_pipeline_crawl_delegates_to_orchestrator():
    orch = _FakeOrchestrator()
    pipe = CommandPipeline(orch)
    result = await pipe.run_crawl(target=object())
    assert result == ["ep"]
    assert orch.calls == ["recon"]


async def test_pipeline_connector_delegates_to_orchestrator():
    orch = _FakeOrchestrator()
    pipe = CommandPipeline(orch)
    result = await pipe.run_connector("nuclei", "http://ex.com", {})
    assert result == ["cfinding"]
    assert orch.calls == ["run_connector:nuclei"]
    assert pipe.stages == PipelineStage.ordered()


async def test_pipeline_scan_agrees_with_the_cli_against_a_real_target(tmp_path):
    """The end-to-end version of the contract above, with no fakes involved.

    Against the ground-truth site a scan records findings during recon. What the
    pipeline returns has to be what the CLI would print for the same scan;
    anything less is a count an operator would have to reconcile by hand.
    """
    from spyder.core.config import CrawlConfig, SpyderConfig
    from spyder.core.models import Target
    from spyder.core.orchestrator import Orchestrator
    from verification.groundtruth.server import ground_truth_server

    with ground_truth_server() as base:
        cfg = SpyderConfig()
        cfg.home = tmp_path
        cfg.crawl = CrawlConfig(
            max_depth=2, max_pages=60, concurrency=10, rate_limit_per_sec=1000.0
        )
        orch = Orchestrator(cfg, workspace="pipeline-scan")
        try:
            returned = await CommandPipeline(orch).run_scan(Target(base_url=base))
            # What `_cmd_scan` and the dashboard both print.
            assert returned == orch.findings()
            assert returned, "the ground-truth site yields findings; none were returned"
        finally:
            orch.close()
