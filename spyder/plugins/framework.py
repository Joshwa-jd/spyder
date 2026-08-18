"""Plugin framework: dynamically loadable analyzers, reporters, and connectors.

A plugin is any Python module exposing a top-level `register(registry)` function,
or a subclass of one of the base plugin types discovered in a plugin directory.
"""
from __future__ import annotations

import importlib.util
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.models import Endpoint, Finding
from ..utils.logging import get_logger

log = get_logger("plugins")


class ConnectorError(RuntimeError):
    """Raised when a connector cannot run (missing binary, failed validation, …).

    Canonical home for the exception so there is a single class shared by the
    plugin layer, the ``ExternalToolConnector`` base, and every connector.
    ``spyder.connectors.base`` re-exports it for backward-compatible imports.
    """


@dataclass
class ConnectorValidation:
    """Outcome of a connector's pre-flight ``validate()`` check."""

    ok: bool
    errors: list[str] = field(default_factory=list)

    @classmethod
    def success(cls) -> ConnectorValidation:
        return cls(ok=True, errors=[])

    @classmethod
    def failure(cls, *errors: str) -> ConnectorValidation:
        return cls(ok=False, errors=[e for e in errors if e])


class Plugin(ABC):  # noqa: B024 - abstract root: subclasses add the abstract methods
    """Base class for all plugins.

    Deliberately declares no abstract methods of its own — it exists to give the
    plugin hierarchy a common ``ABCMeta`` root and shared metadata. The concrete
    contracts (``analyze``, ``run``, ``render``, …) are abstract on the subclasses.
    """

    name: str = "unnamed"
    version: str = "0.0.0"

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "type": type(self).__bases__[0].__name__}


class AnalyzerPlugin(Plugin):
    """Inspects endpoints/transactions and emits findings."""

    @abstractmethod
    async def analyze(self, endpoints: list[Endpoint], context: dict[str, Any]) -> list[Finding]:
        ...


class ReporterPlugin(Plugin):
    """Renders findings to some output format."""

    @abstractmethod
    def render(self, findings: list[Finding], context: dict[str, Any]) -> str:
        ...


class ConnectorPlugin(Plugin):
    """Bridges to an external analyst tool (sqlmap, nuclei, Burp, ...).

    Every connector exposes the same six-stage lifecycle so callers can treat
    them uniformly regardless of how they reach the underlying tool (subprocess,
    REST API, stdin stream):

        initialize()  → reset per-run state / options
        validate()    → pre-flight checks (target present, binary on PATH, …)
        execute()     → run the tool and return findings
        parse()       → normalize raw tool output into findings
        cleanup()     → release any per-run resources
        status()      → report readiness/availability

    :meth:`invoke` runs the stages in order and is what the orchestrator calls.
    :meth:`run` remains the low-level execution contract each connector
    implements; ``execute`` delegates to it by default, so existing connectors
    keep working unchanged while gaining the full lifecycle.
    """

    # --- stage 1: initialize -------------------------------------------------
    def initialize(self, options: dict[str, Any] | None = None) -> None:
        """Reset per-run state and stash the options for this invocation."""
        self._options: dict[str, Any] = dict(options or {})
        self._last_ok: bool | None = None
        self._initialized = True
        self.on_initialize()

    def on_initialize(self) -> None:
        """Override hook: subclass setup after options are stored."""

    # --- stage 2: validate ---------------------------------------------------
    def validate(
        self, target: str, options: dict[str, Any] | None = None
    ) -> ConnectorValidation:
        """Pre-flight check. Base contract: a non-empty target is required."""
        if not (target or "").strip():
            return ConnectorValidation.failure("no target provided")
        return ConnectorValidation.success()

    # --- stage 3: execute ----------------------------------------------------
    async def execute(
        self, target: str, options: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Run the tool. Defaults to the connector's :meth:`run` contract."""
        return await self.run(target, dict(options if options is not None else getattr(self, "_options", {})))

    # --- stage 4: parse ------------------------------------------------------
    def parse(self, raw: Any) -> list[Finding]:
        """Normalize raw output into findings.

        Subprocess connectors parse tool stdout in their own ``run``/``_parse``;
        this public hook accepts an already-built list of findings (or anything
        that is not a finding list, which yields none).
        """
        if isinstance(raw, list):
            return [f for f in raw if isinstance(f, Finding)]
        return []

    # --- stage 5: cleanup ----------------------------------------------------
    def cleanup(self) -> None:
        """Release per-run resources (temp files, clients). No-op by default."""
        self.on_cleanup()

    def on_cleanup(self) -> None:
        """Override hook: subclass teardown after a run."""

    # --- stage 6: status -----------------------------------------------------
    def available(self) -> bool:
        """Whether the connector can run. API-based connectors are always ready;
        subprocess connectors override this to check the binary is on PATH."""
        return True

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "type": "connector",
            "available": self.available(),
            "initialized": getattr(self, "_initialized", False),
            "last_ok": getattr(self, "_last_ok", None),
        }

    # --- low-level contract every connector implements -----------------------
    @abstractmethod
    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        ...

    # --- orchestrated full-lifecycle entry point -----------------------------
    async def invoke(
        self, target: str, options: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Run the full lifecycle in order and return findings.

        ``initialize → validate → execute → cleanup``. Validation failure raises
        :class:`ConnectorError` (surfaced to the operator as a clean message).
        ``cleanup`` always runs. Behaviour is identical to calling ``run``
        directly for connectors that don't override the stages — the lifecycle
        adds pre-flight validation and setup/teardown hooks around it.
        """
        opts = dict(options or {})
        self.initialize(opts)
        result = self.validate(target, opts)
        if not result.ok:
            self._last_ok = False
            self.cleanup()
            raise ConnectorError(
                f"{self.name}: cannot run — {'; '.join(result.errors)}"
            )
        try:
            findings = await self.execute(target, opts)
            self._last_ok = True
            return findings
        except Exception:
            self._last_ok = False
            raise
        finally:
            self.cleanup()


class ReconPlugin(Plugin):
    """Enriches the recon inventory — extra discovery or endpoint intelligence.

    Runs after the crawl and may emit findings or annotate context. Distinct from
    AnalyzerPlugin in intent: recon plugins expand attack-surface knowledge rather
    than judge it.
    """

    @abstractmethod
    async def recon(self, endpoints: list[Endpoint], context: dict[str, Any]) -> list[Finding]:
        ...


class ReplayPlugin(Plugin):
    """Reacts to replayed transactions (e.g. custom diffing or alerting)."""

    @abstractmethod
    async def on_replay(self, context: dict[str, Any]) -> None:
        ...


class DashboardWidgetPlugin(Plugin):
    """Contributes a live panel to the Textual dashboard.

    ``render(state, context)`` returns a Rich renderable shown in a HUD panel
    titled by ``self.name``. Called on each dashboard refresh; must be cheap and
    side-effect free.
    """

    @abstractmethod
    def render(self, state: Any, context: dict[str, Any]) -> Any:
        ...


class ReplayAnalyzerPlugin(Plugin):
    """Analyzes a replay record and may emit findings.

    Called for each replayed request with the enriched ReplayRecord; lets plugins
    flag interesting replay behaviour (e.g. status flips, reflections) for review.
    """

    @abstractmethod
    async def analyze_replay(self, record: Any, context: dict[str, Any]) -> list[Finding]:
        ...


class ReplayVisualizationPlugin(Plugin):
    """Renders a visualization from replay history (timing graphs, timelines)."""

    @abstractmethod
    def visualize_replay(self, history: Any, context: dict[str, Any]) -> Any:
        ...


class VisualizationPlugin(Plugin):
    """Produces a standalone visualization artifact from workspace state."""

    @abstractmethod
    def visualize(self, state: Any, context: dict[str, Any]) -> Any:
        ...


# Abstract base contracts that must never be auto-instantiated during discovery.
_BASE_PLUGIN_TYPES: tuple[type, ...] = (
    Plugin, AnalyzerPlugin, ReporterPlugin, ConnectorPlugin,
    ReconPlugin, ReplayPlugin, DashboardWidgetPlugin, VisualizationPlugin,
    ReplayAnalyzerPlugin, ReplayVisualizationPlugin,
)


class PluginRegistry:
    def __init__(self) -> None:
        self.analyzers: dict[str, AnalyzerPlugin] = {}
        self.reporters: dict[str, ReporterPlugin] = {}
        self.connectors: dict[str, ConnectorPlugin] = {}
        self.recon: dict[str, ReconPlugin] = {}
        self.replay: dict[str, ReplayPlugin] = {}
        self.widgets: dict[str, DashboardWidgetPlugin] = {}
        self.visualizers: dict[str, VisualizationPlugin] = {}
        self.replay_analyzers: dict[str, ReplayAnalyzerPlugin] = {}
        self.replay_visualizers: dict[str, ReplayVisualizationPlugin] = {}

    def add(self, plugin: Plugin) -> None:
        # Order matters: check the most specific contracts first.
        if isinstance(plugin, AnalyzerPlugin):
            self.analyzers[plugin.name] = plugin
        elif isinstance(plugin, ReporterPlugin):
            self.reporters[plugin.name] = plugin
        elif isinstance(plugin, ConnectorPlugin):
            self.connectors[plugin.name] = plugin
        elif isinstance(plugin, ReconPlugin):
            self.recon[plugin.name] = plugin
        elif isinstance(plugin, ReplayAnalyzerPlugin):
            self.replay_analyzers[plugin.name] = plugin
        elif isinstance(plugin, ReplayVisualizationPlugin):
            self.replay_visualizers[plugin.name] = plugin
        elif isinstance(plugin, ReplayPlugin):
            self.replay[plugin.name] = plugin
        elif isinstance(plugin, DashboardWidgetPlugin):
            self.widgets[plugin.name] = plugin
        elif isinstance(plugin, VisualizationPlugin):
            self.visualizers[plugin.name] = plugin
        else:
            raise TypeError(f"Unknown plugin type: {type(plugin)}")
        log.info("registered plugin: %s (%s)", plugin.name, type(plugin).__bases__[0].__name__)

    def load_dir(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in directory.glob("*.py"):
            if path.name.startswith("_"):
                continue
            count += self._load_file(path)
        return count

    def _load_file(self, path: Path) -> int:
        spec = importlib.util.spec_from_file_location(f"spyder_plugin_{path.stem}", path)
        if not spec or not spec.loader:
            return 0
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # plugins are third-party; isolate failures
            log.error("failed to load plugin %s: %s", path.name, exc)
            return 0
        loaded = 0
        if hasattr(module, "register"):
            module.register(self)
            loaded += 1
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Plugin) and obj not in _BASE_PLUGIN_TYPES \
                    and not inspect.isabstract(obj):
                try:
                    self.add(obj())
                    loaded += 1
                except Exception as exc:
                    log.error("failed to instantiate %s: %s", obj.__name__, exc)
        return loaded

    def summary(self) -> dict[str, list[str]]:
        return {
            "analyzers": list(self.analyzers),
            "reporters": list(self.reporters),
            "connectors": list(self.connectors),
            "recon": list(self.recon),
            "replay": list(self.replay),
            "widgets": list(self.widgets),
            "visualizers": list(self.visualizers),
            "replay_analyzers": list(self.replay_analyzers),
            "replay_visualizers": list(self.replay_visualizers),
        }
