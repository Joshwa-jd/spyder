"""The orchestration engine — coordinates SPYDER's subsystems into workflows.

This is the 'workflow operating system' layer: it wires together the HTTP client,
crawler, parameter prober, analyzers, connectors, recon intelligence, replay, and
workspace persistence. An optional EventBus lets reactive consumers (the Textual
dashboard, plugins) observe the pipeline live without changing call sites.
"""
from __future__ import annotations

import time
from typing import Any

from ..analysis import intel as intel_mod
from ..analysis.discovery import DiscoverySummary, summarize_discovery
from ..analysis.fingerprint import fingerprint
from ..analysis.graph import (
    Graph,
    build_attack_surface_graph,
    build_cluster_graph,
    build_tech_graph,
)
from ..analysis.intel import AttackSurface, EndpointIntel, ParamAnalytics, TechSummary
from ..analysis.jsintel import JsReconEngine, JsReconResult
from ..analysis.replay import ReplayAnalytics, ReplayHistory, ReplayRecord, record_replay
from ..connectors.burp import BurpConnector
from ..connectors.nuclei import NucleiConnector
from ..connectors.recon import RECON_CONNECTORS
from ..connectors.sqlmap import SqlmapConnector
from ..core.config import SpyderConfig
from ..core.events import EventBus, EventType
from ..core.models import Endpoint, Finding, Severity, Target
from ..crawler.engine import Crawler
from ..crawler.params import ParameterProber
from ..http.client import HTTPClient, Transaction
from ..plugins.framework import PluginRegistry
from ..reporting.catalogue import apply_to
from ..utils.logging import get_logger
from ..utils.scope import ScopeGuard
from ..validation.endpoints import (
    ValidatedEndpoint,
    deduplicate_endpoints,
    validate_intel,
)
from ..validation.fingerprint import TechConfidence, validate_technologies
from ..validation.summary import SignalQuality, signal_quality
from ..workspace.layout import WorkspacePaths
from ..workspace.manager import WorkspaceManager

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(
        self,
        config: SpyderConfig,
        workspace: str,
        events: EventBus | None = None,
    ):
        self.config = config
        self.workspace_name = workspace
        self.events = events
        self.wm = WorkspaceManager(config.db_path)
        self.ws_id = self.wm.create(workspace)
        self.paths = WorkspacePaths.for_workspace(config.workspaces_dir, workspace).ensure()
        self.registry = PluginRegistry()
        self._register_builtin_connectors()
        for d in config.plugin_dirs:
            self.registry.load_dir(d)
        self.last_transactions: list[Transaction] = []
        self.last_endpoints: list[Endpoint] = []
        self.last_intel: list[EndpointIntel] = []
        self.last_target: str | None = None
        self.last_jsintel: JsReconResult | None = None
        self.duplicates_suppressed = 0
        self.replay_history = ReplayHistory()
        self._load_replay_history()

    def _register_builtin_connectors(self) -> None:
        for connector in (NucleiConnector(), SqlmapConnector(), BurpConnector()):
            self.registry.add(connector)
        for connector_cls in RECON_CONNECTORS:
            self.registry.add(connector_cls())

    def _scope(self, target: Target) -> ScopeGuard:
        hosts = target.scope_hosts or [target.host]
        return ScopeGuard(hosts, target.include_subdomains)

    def _emit(self, type: EventType, message: str = "", **data) -> None:
        if self.events:
            self.events.emit(type, message, source="orchestrator", **data)

    @staticmethod
    def _merge_endpoints(base: list[Endpoint], extra: list[Endpoint]) -> list[Endpoint]:
        """Union two endpoint lists, deduplicating by fingerprint."""
        seen = {ep.fingerprint() for ep in base}
        merged = list(base)
        for ep in extra:
            fp = ep.fingerprint()
            if fp not in seen:
                seen.add(fp)
                merged.append(ep)
        return merged

    async def recon(self, target: Target) -> list[Endpoint]:
        """Full recon pass: crawl, discover params, probe reflections, fingerprint."""
        self._emit(EventType.RECON_START, f"recon → {target.base_url}", target=str(target.base_url))
        started = time.monotonic()
        scope = self._scope(target)
        async with HTTPClient(self.config.http, self.config.effective_rate_limit) as client:
            crawler = Crawler(client, scope, self.config.crawl, events=self.events)
            endpoints = await crawler.crawl(str(target.base_url))

            if not self.config.passive_mode:
                prober = ParameterProber(client)
                for ep in endpoints:
                    if ep.params:
                        await prober.probe(ep)
                        self._emit(
                            EventType.PARAM_PROBED,
                            f"probed {len(ep.params)} params · {ep.url}",
                            url=ep.url,
                        )

            # Passive fingerprint from the seed response.
            seed = await client.get(str(target.base_url))
            fp = fingerprint(seed)
            if fp.dbms_hints or fp.waf_hints or fp.entities:
                self._emit(
                    EventType.FINGERPRINT,
                    "passive fingerprint captured",
                    technologies=fp.technologies,
                    waf=fp.waf_hints,
                    dbms=fp.dbms_hints,
                )
                scored = validate_technologies(fp.entities)
                self.wm.save_finding(
                    self.ws_id,
                    Finding(
                        **apply_to(
                            "passive-fingerprint",
                            title="Passive fingerprint",
                            severity=Severity.INFO,
                            endpoint=str(target.base_url),
                            description="Technologies and protective services inferred passively.",
                            evidence={
                                "technologies": fp.technologies,
                                # The evidence behind each claim, so the confidence
                                # model can rescore without refetching the response.
                                "technology_entities": [t.to_dict() for t in fp.entities],
                                "waf_hints": fp.waf_hints,
                                "dbms_hints": fp.dbms_hints,
                            },
                            # The inventory is only as good as its weakest claim.
                            confidence=(min(scored, key=lambda t: t.score).level.value
                                        if scored else "low"),
                            confidence_score=(min(t.score for t in scored) if scored else 0),
                        )
                    ),
                )
                # A disclosed *version* is a weakness in its own right; a bare
                # technology inventory is not. Raise it only when one was seen.
                versions = {t.name: t.version for t in fp.entities if t.version}
                # Score the claim from the evidence that supports *it*. Taking
                # max() over every technology let the finding inherit the score
                # of an entity that disclosed no version and formed no part of
                # the claim, printing a confidence its own evidence block did
                # not back up.
                versioned = [t for t in scored if t.version]
                if versions:
                    self.wm.save_finding(
                        self.ws_id,
                        Finding(
                            **apply_to(
                                "version-disclosure",
                                title="Product versions disclosed",
                                severity=Severity.LOW,
                                endpoint=str(target.base_url),
                                description=(
                                    "The server volunteered exact product versions, narrowing "
                                    "an attacker's search for applicable known vulnerabilities."
                                ),
                                evidence={
                                    "versions": versions,
                                    "disclosed_by": [
                                        e.to_dict() for t in fp.entities if t.version
                                        for e in t.evidence
                                    ],
                                },
                                confidence=(max(versioned, key=lambda t: t.score).level.value
                                            if versioned else "medium"),
                                confidence_score=(
                                    max(t.score for t in versioned) if versioned else 50
                                ),
                            )
                        ),
                    )

            # JavaScript recon intelligence — mine discovered JS for hidden surface.
            js_urls = [
                ep.url for ep in endpoints
                if ep.url.lower().split("?")[0].endswith(".js")
                or "javascript" in (ep.content_type or "").lower()
            ]
            if js_urls and self.config.crawl.extract_js_endpoints:
                js_engine = JsReconEngine(client, scope, events=self.events)
                self.last_jsintel = await js_engine.analyze_urls(js_urls, str(target.base_url))
                endpoints = self._merge_endpoints(endpoints, self.last_jsintel.endpoints)
                if self.last_jsintel.intel.secrets:
                    self.wm.save_finding(
                        self.ws_id,
                        Finding(
                            title="Secrets referenced in JavaScript",
                            severity=Severity.MEDIUM,
                            endpoint=str(target.base_url),
                            description=(
                                "Potential secret/token patterns were observed in served "
                                "JavaScript. Values are redacted; verify and rotate as needed."
                            ),
                            evidence={
                                "secrets": [
                                    {"kind": s.kind, "value": s.value, "confidence": s.confidence,
                                     "source": s.source, "level": s.level, "score": s.score,
                                     "reasons": list(s.reasons)}
                                    for s in self.last_jsintel.intel.secrets
                                ],
                            },
                            cwe=["CWE-615"],
                            owasp=["A05:2021-Security Misconfiguration"],
                            remediation="Remove secrets from client-side code; rotate exposed credentials.",
                        ),
                    )

            self.last_transactions = list(client.transactions)

        # Logical de-duplication: collapse routes that differ only by record id,
        # query ordering, casing, or trailing slash so the inventory counts real
        # endpoints rather than string variants.
        raw_count = len(endpoints)
        endpoints, _dedup_counts = deduplicate_endpoints(endpoints)
        self.duplicates_suppressed = raw_count - len(endpoints)
        if self.duplicates_suppressed:
            self._emit(
                EventType.INTEL,
                f"suppressed {self.duplicates_suppressed} duplicate routes",
                duplicates=self.duplicates_suppressed,
            )

        self.last_target = str(target.base_url)
        self.last_endpoints = endpoints
        self.last_intel = intel_mod.classify_all(endpoints)
        saved = self.wm.save_endpoints(self.ws_id, endpoints)
        duration = time.monotonic() - started
        if endpoints:
            status = "complete"
        elif self.last_transactions:
            status = "empty"
        else:
            status = "unreachable"
        self.wm.log_scan(
            self.ws_id,
            "recon",
            f"{len(endpoints)} endpoints ({saved} new)",
            target=str(target.base_url),
            endpoints=len(endpoints),
            findings=len(self.wm.get_findings(self.ws_id)),
            duration=duration,
            status=status,
        )
        self.paths.append_timeline("recon", f"{len(endpoints)} endpoints", target=str(target.base_url))
        self._emit(
            EventType.RECON_DONE,
            f"recon complete · {len(endpoints)} endpoints",
            endpoints=len(endpoints),
            new=saved,
            high_interest=sum(1 for i in self.last_intel if i.high_interest),
        )
        return endpoints

    async def run_analyzers(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings: list[Finding] = []
        ctx = {"config": self.config, "workspace": self.workspace_name}
        for name, analyzer in self.registry.analyzers.items():
            try:
                produced = await analyzer.analyze(endpoints, ctx)
                findings.extend(produced)
                for f in produced:
                    self.wm.save_finding(self.ws_id, f)
                log.info("analyzer %s produced %d findings", name, len(produced))
                self._emit(
                    EventType.ANALYZER_DONE,
                    f"analyzer {name}: {len(produced)} findings",
                    analyzer=name,
                    findings=len(produced),
                )
            except Exception as exc:
                log.error("analyzer %s failed: %s", name, exc)
                self._emit(EventType.ERROR, f"analyzer {name} failed: {exc}", analyzer=name)
        return findings

    async def run_connector(self, name: str, target: str, options: dict[str, Any]) -> list[Finding]:
        connector = self.registry.connectors.get(name)
        if not connector:
            available = ", ".join(self.registry.connectors) or "none"
            raise ValueError(f"No connector named '{name}'. Available: {available}")
        # Inject the event bus so recon connectors can stream discoveries live.
        if hasattr(connector, "events"):
            connector.events = self.events
        self._emit(EventType.CONNECTOR_START, f"connector {name} → {target}", connector=name, target=target)
        # Drive the full connector lifecycle (initialize → validate → execute →
        # cleanup) rather than calling run() directly, so pre-flight validation
        # and setup/teardown hooks always fire uniformly across connectors.
        findings = await connector.invoke(target, options)
        for f in findings:
            self.wm.save_finding(self.ws_id, f)
        self.wm.log_scan(
            self.ws_id,
            name,
            f"{len(findings)} findings",
            target=target,
            findings=len(findings),
            status="complete",
        )
        self.paths.append_timeline("connector", f"{name}: {len(findings)} findings", connector=name)
        self._emit(
            EventType.CONNECTOR_DONE,
            f"connector {name}: {len(findings)} findings",
            connector=name,
            findings=len(findings),
        )
        return findings

    def _load_replay_history(self) -> None:
        """Rehydrate persisted replay records (notes/bookmarks/tags survive sessions)."""
        try:
            for d in self.wm.get_replays(self.ws_id):
                self.replay_history.load_record(ReplayRecord.from_dict(d))
        except Exception as exc:  # malformed persisted data must not block startup
            log.debug("replay history load failed: %s", exc)

    def _persist_replay(self, record: ReplayRecord) -> None:
        self.wm.save_replay(self.ws_id, record.id, record.to_dict())

    async def replay(self, index: int) -> ReplayRecord:
        """Re-issue a recorded transaction and capture an enriched ReplayRecord."""
        if index < 0 or index >= len(self.last_transactions):
            raise IndexError(f"replay index out of range (0–{len(self.last_transactions) - 1})")
        original = self.last_transactions[index]
        async with HTTPClient(self.config.http, record=False) as client:
            replayed = await client.replay(original)
        record = record_replay(index, original, replayed)
        self.replay_history.add(record)
        self._persist_replay(record)
        self.paths.append_timeline("replay", f"#{record.id} {record.url}", status=record.replayed_status)
        self._emit(
            EventType.REPLAY,
            f"replay #{record.id}: {record.original_status} → {record.replayed_status}",
            id=record.id,
            index=index,
            similarity=record.similarity,
            timing_ms=record.timing_ms,
            reflected=len(record.reflected),
        )
        return record

    # --- replay workbench operations (persisted) ---
    def replay_tag(self, rid: int, *tags: str) -> ReplayRecord | None:
        rec = self.replay_history.tag(rid, *tags)
        if rec:
            self._persist_replay(rec)
            self._emit(EventType.REPLAY, f"tagged #{rid}: {', '.join(tags)}", id=rid)
        return rec

    def replay_bookmark(self, rid: int, on: bool = True) -> ReplayRecord | None:
        rec = self.replay_history.bookmark(rid, on)
        if rec:
            self._persist_replay(rec)
            self._emit(EventType.REPLAY, f"{'bookmarked' if on else 'unbookmarked'} #{rid}", id=rid)
        return rec

    def replay_note(self, rid: int, note: str) -> ReplayRecord | None:
        rec = self.replay_history.annotate(rid, note)
        if rec:
            self._persist_replay(rec)
        return rec

    def replay_group(self, rid: int, group: str | None) -> ReplayRecord | None:
        rec = self.replay_history.set_group(rid, group)
        if rec:
            self._persist_replay(rec)
        return rec

    def replay_analytics(self) -> ReplayAnalytics:
        return self.replay_history.analytics()

    def replay_records(self) -> list[ReplayRecord]:
        return self.replay_history.records

    def replay_get(self, rid: int) -> ReplayRecord | None:
        return self.replay_history.get(rid)

    # --- intelligence accessors (computed from current state) ---
    def findings(self) -> list[Finding]:
        return self.wm.get_findings(self.ws_id)

    def endpoints(self) -> list[Endpoint]:
        """Current endpoint inventory — last scan, else loaded from the workspace."""
        if self.last_endpoints:
            return self.last_endpoints
        return self.wm.get_endpoints(self.ws_id)

    def intel(self) -> list[EndpointIntel]:
        eps = self.endpoints()
        if self.last_intel and self.last_endpoints:
            return self.last_intel
        return intel_mod.classify_all(eps)

    def attack_surface(self) -> AttackSurface:
        return intel_mod.attack_surface(self.endpoints(), self.intel())

    def param_analytics(self) -> ParamAnalytics:
        return intel_mod.analyze_parameters(self.endpoints())

    def tech_summary(self) -> TechSummary:
        return intel_mod.summarize_technologies(self.findings())

    def js_intel(self) -> JsReconResult:
        return self.last_jsintel or JsReconResult()

    # --- validation / confidence accessors ---
    def validated_endpoints(self) -> list[ValidatedEndpoint]:
        """Endpoints enriched with confidence + importance, most-trustworthy first."""
        return validate_intel(self.intel())

    def tech_confidence(self) -> list[TechConfidence]:
        """Fingerprinted technologies scored by the evidence behind each claim."""
        summary = self.tech_summary()
        return validate_technologies(summary.entities, corroborations=summary.occurrences)

    def signal_quality(self) -> SignalQuality:
        """Platform-wide intelligence reliability snapshot for the dashboard."""
        validated = self.validated_endpoints()
        js = self.js_intel()
        techs = self.tech_confidence()
        return signal_quality(
            validated,
            secret_levels=js.intel.secret_levels,
            duplicates_suppressed=self.duplicates_suppressed,
            replay_analytics=self.replay_history.analytics(),
            tech_verified=sum(1 for t in techs if t.verified),
            tech_total=len(techs),
        )

    def discovery_summary(self) -> DiscoverySummary:
        return summarize_discovery(self.findings())

    # --- visual intelligence graphs (deterministic) ---
    def _confidence_by_url(self) -> dict[str, int]:
        return {v.url: v.score for v in self.validated_endpoints()}

    def intelligence_graph(self) -> Graph:
        """Host → route-group → endpoint attack-surface map (confidence-aware)."""
        return build_attack_surface_graph(
            self.intel(), confidence_by_url=self._confidence_by_url()
        )

    def cluster_graph(self) -> Graph:
        """Endpoints grouped by attack-surface class (auth/admin/api/…)."""
        return build_cluster_graph(
            self.intel(), confidence_by_url=self._confidence_by_url()
        )

    def technology_graph(self) -> Graph:
        """Host → attributed-technology relationship map."""
        target = self.last_endpoints[0].url if self.last_endpoints else "target"
        return build_tech_graph(self.tech_summary().technologies, host=target)

    def close(self) -> None:
        self.wm.close()
