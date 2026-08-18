"""SPYDER persistent Textual dashboard — the cinematic recon intelligence OS.

A fullscreen, reactive, split-pane SOC console that runs on top of the existing
orchestrator and event bus. It does not replace the REPL or CLI — it is a third
surface (`spyder dashboard`) that streams the recon pipeline live and renders
attack-surface intelligence.

Layout
    ┌───────────────── TOP HEADER (brand · workspace · metrics · status) ─────────────────┐
    │ LEFT: live event stream │ CENTER: recon/findings/surface/params │ RIGHT: tech/fp/HI │
    ├──────────────────────────── COMMAND OUTPUT (orchestration log) ─────────────────────┤
    └──────────────── FOOTER: command prompt · mode · profile · runtime ──────────────────┘

All colour comes from ``spyder.ui.theme`` — no literals here.
"""
from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from rich.table import Table
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Input, RichLog, Static

from ..analysis.discovery import DiscoverySummary
from ..analysis.graph import Graph
from ..analysis.intel import (
    AttackSurface,
    EndpointIntel,
    ParamAnalytics,
    TechSummary,
)
from ..analysis.jsintel import JsReconResult
from ..analysis.replay import ReplayAnalytics, ReplayRecord
from ..core.config import SpyderConfig
from ..core.events import EventBus, EventType
from ..core.models import Endpoint, Finding, Severity, parse_target
from ..core.orchestrator import Orchestrator
from ..validation.summary import SignalQuality
from . import theme
from .theme import (
    DIM_GREY,
    INFO_BLUE,
    MUTED,
    NEON_RED,
    OFF_WHITE,
    SEVERITY_STYLES,
    SUCCESS,
    WARNING,
)

# ---------------------------------------------------------------------------
# State snapshot
# ---------------------------------------------------------------------------


@dataclass
class DashboardState:
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    intel: list[EndpointIntel] = field(default_factory=list)
    surface: AttackSurface = field(default_factory=AttackSurface)
    params: ParamAnalytics = field(default_factory=ParamAnalytics)
    tech: TechSummary = field(default_factory=TechSummary)
    js: JsReconResult = field(default_factory=JsReconResult)
    discovery: DiscoverySummary = field(default_factory=DiscoverySummary)
    connectors: list[str] = field(default_factory=list)
    replay: list[ReplayRecord] = field(default_factory=list)
    replay_analytics: ReplayAnalytics = field(default_factory=ReplayAnalytics)
    surface_graph: Graph = field(default_factory=Graph)
    cluster_graph: Graph = field(default_factory=Graph)
    quality: SignalQuality = field(default_factory=SignalQuality)
    ws_summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Controller — wraps the orchestrator + event bus for the dashboard
# ---------------------------------------------------------------------------


class DashboardController:
    """Owns the live orchestrator + event bus and produces UI snapshots."""

    def __init__(self, config: SpyderConfig, workspace: str = "default", profile: str = "default"):
        self.config = config
        self.workspace = workspace
        self.profile = profile
        self.events = EventBus()
        self.orch = Orchestrator(config, workspace, events=self.events)
        self.scanning = False

    def snapshot(self) -> DashboardState:
        eps = self.orch.endpoints()
        findings = self.orch.findings()
        intel = self.orch.intel()
        return DashboardState(
            endpoints=eps,
            findings=findings,
            intel=intel,
            surface=self.orch.attack_surface(),
            params=self.orch.param_analytics(),
            tech=self.orch.tech_summary(),
            js=self.orch.js_intel(),
            discovery=self.orch.discovery_summary(),
            connectors=sorted(self.orch.registry.connectors),
            replay=self.orch.replay_history.records,
            replay_analytics=self.orch.replay_history.analytics(),
            surface_graph=self.orch.intelligence_graph(),
            cluster_graph=self.orch.cluster_graph(),
            quality=self.orch.signal_quality(),
            ws_summary=self.orch.paths.summary(),
        )

    def close(self) -> None:
        self.orch.close()


# ---------------------------------------------------------------------------
# Reusable HUD panel widget
# ---------------------------------------------------------------------------


class HudPanel(Static):
    """A bordered HUD panel with a neon title, content set via ``.update()``."""

    def __init__(self, title: str, *, accent: bool = False, **kwargs) -> None:
        super().__init__("", **kwargs)
        self._title = title
        self.add_class("hud-panel-accent" if accent else "hud-panel")

    def on_mount(self) -> None:
        self.border_title = f"◢ {self._title.upper()} ◣"


# ---------------------------------------------------------------------------
# Renderable builders (theme-driven, no hardcoded colours)
# ---------------------------------------------------------------------------


def _grid() -> Table:
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(justify="left", ratio=1)
    g.add_column(justify="right")
    return g


def _row(g: Table, key: str, value, *, value_color: str = NEON_RED) -> None:
    g.add_row(f"[{DIM_GREY}]{key}[/]", f"[{value_color}]{value}[/]")


def _short_url(url: str, maxlen: int = 52) -> str:
    p = urlparse(url)
    s = p.path or "/"
    if p.query:
        s += "?" + p.query
    return s if len(s) <= maxlen else s[: maxlen - 1] + "…"


def render_recon_summary(state: DashboardState) -> Table:
    s = state.surface
    g = _grid()
    _row(g, "endpoints", s.total_endpoints)
    _row(g, "with parameters", s.with_params)
    _row(g, "state-changing", s.write_endpoints)
    _row(g, "reflected params", s.reflected_params, value_color=WARNING)
    _row(g, "high-interest", s.high_interest, value_color=WARNING)
    return g


def render_findings_summary(state: DashboardState) -> Table:
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for f in state.findings:
        counts[f.severity] += 1
    g = _grid()
    for sev in sorted(Severity, key=lambda s: s.rank, reverse=True):
        style = SEVERITY_STYLES[sev]
        g.add_row(f"[{style}]{sev.value.upper()}[/]", f"[{NEON_RED}]{counts[sev]}[/]")
    g.add_row(f"[{OFF_WHITE}]total[/]", f"[{NEON_RED}]{len(state.findings)}[/]")
    return g


def render_attack_surface(state: DashboardState) -> Table:
    s = state.surface
    g = _grid()
    if not s.total_endpoints:
        g.add_row(f"[{MUTED}]no recon data — run 'scan <url>'[/]", "")
        return g
    methods = "  ".join(f"{m}:{n}" for m, n in sorted(s.by_method.items()))
    g.add_row(f"[{DIM_GREY}]methods[/]", f"[{OFF_WHITE}]{methods or '—'}[/]")
    for cls, n in sorted(s.by_class.items(), key=lambda kv: kv[1], reverse=True):
        _row(g, f"class · {cls}", n, value_color=WARNING if cls not in ("static", "generic") else DIM_GREY)
    return g


def render_param_analytics(state: DashboardState) -> Table:
    p = state.params
    g = _grid()
    if not p.total:
        g.add_row(f"[{MUTED}]no parameters discovered yet[/]", "")
        return g
    _row(g, "total params", p.total)
    _row(g, "unique names", p.unique_names)
    _row(g, "reflected", p.reflected, value_color=WARNING)
    locs = "  ".join(f"{k}:{v}" for k, v in sorted(p.by_location.items()))
    g.add_row(f"[{DIM_GREY}]by location[/]", f"[{OFF_WHITE}]{locs or '—'}[/]")
    if p.interesting:
        top = "  ".join(f"{name}×{cnt}" for name, cnt in p.interesting[:6])
        g.add_row(f"[{DIM_GREY}]of interest[/]", f"[{WARNING}]{top}[/]")
    return g


def render_tech_summary(state: DashboardState) -> Table:
    t = state.tech
    g = _grid()
    if not t.technologies:
        g.add_row(f"[{MUTED}]no passive fingerprint yet[/]", "")
        return g
    for label, value in sorted(t.technologies.items()):
        _row(g, label, value, value_color=OFF_WHITE)
    return g


def render_fingerprints(state: DashboardState) -> Table:
    t = state.tech
    g = _grid()
    if not (t.waf or t.dbms):
        g.add_row(f"[{MUTED}]no protective/db signatures[/]", "")
        return g
    if t.waf:
        g.add_row(f"[{DIM_GREY}]WAF / CDN[/]", f"[{WARNING}]{', '.join(t.waf)}[/]")
    if t.dbms:
        g.add_row(f"[{DIM_GREY}]DBMS hints[/]", f"[{NEON_RED}]{', '.join(t.dbms)}[/]")
    return g


def render_high_interest(state: DashboardState) -> Table:
    intels = [i for i in state.intel if i.high_interest][:14]
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(justify="right", width=4)
    g.add_column(width=6)
    g.add_column(ratio=1)
    if not intels:
        g.add_row("", "", f"[{MUTED}]no high-interest endpoints[/]")
        return g
    for i in intels:
        g.add_row(
            f"[{NEON_RED}]{i.score}[/]",
            f"[{OFF_WHITE}]{i.method}[/]",
            f"[{DIM_GREY}]{_short_url(i.url)}[/] [{WARNING}]{i.primary_class.value}[/]",
        )
    return g


def render_js_intel(state: DashboardState) -> Table:
    c = state.js.counts
    g = _grid()
    if not state.js.files_analyzed:
        g.add_row(f"[{MUTED}]no JS analyzed — run 'scan <url>'[/]", "")
        return g
    _row(g, "JS files", c["files"])
    _row(g, "routes", c["endpoints"])
    _row(g, "API routes", c["api_routes"], value_color=WARNING)
    _row(g, "graphql refs", c["graphql"], value_color=WARNING)
    _row(g, "websockets", c["websockets"])
    _row(g, "source maps", c["source_maps"])
    _row(g, "cloud buckets", c["buckets"], value_color=WARNING)
    _row(g, "secrets", c["secrets"], value_color=NEON_RED if c["secrets"] else DIM_GREY)
    return g


def render_api_map(state: DashboardState) -> Table:
    routes = sorted(state.js.intel.api_routes)[:16]
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(ratio=1)
    if not routes:
        g.add_row(f"[{MUTED}]no API routes mined from JS[/]")
        return g
    for r in routes:
        g.add_row(f"[{INFO_BLUE}]›[/] [{OFF_WHITE}]{_short_url(r, 60)}[/]")
    return g


def render_secrets(state: DashboardState) -> Table:
    secrets = state.js.intel.secrets[:12]
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column()
    g.add_column(ratio=1)
    if not secrets:
        g.add_row("", f"[{MUTED}]no secret patterns detected[/]")
        return g
    for s in secrets:
        # Confidence-weighted: a confirmed/high-confidence secret is the alarming
        # one; lower-confidence candidates are visually de-emphasised.
        level = getattr(s, "level", s.confidence)
        color = {"confirmed": NEON_RED, "high": NEON_RED, "medium": WARNING}.get(level, DIM_GREY)
        score = getattr(s, "score", 0)
        g.add_row(
            f"[{color}]{s.kind}[/]",
            f"[{DIM_GREY}]{s.value}[/] [{MUTED}]· {level} {score}[/]",
        )
    return g


def _bar(pct: float, width: int = 10, color: str = SUCCESS) -> str:
    """A compact neon progress bar for a 0–100 metric."""
    filled = max(0, min(width, round(pct / 100 * width)))
    return f"[{color}]{'█' * filled}[/][{DIM_GREY}]{'░' * (width - filled)}[/]"


def render_signal_quality(state: DashboardState) -> Table:
    """Intelligence reliability widget — verified vs inferred, replay stability."""
    q = state.quality
    g = _grid()
    if not q.endpoints_total and not q.secrets_total and not q.replays_total:
        g.add_row(f"[{MUTED}]no intelligence to validate yet[/]", "")
        return g

    idx = q.reliability_index
    idx_color = SUCCESS if idx >= 70 else WARNING if idx >= 40 else NEON_RED
    g.add_row(
        f"[{OFF_WHITE}]reliability[/]",
        f"{_bar(idx, color=idx_color)} [{idx_color}]{idx} · {q.grade}[/]",
    )
    if q.endpoints_total:
        _row(g, "endpoints verified", f"{q.endpoints_verified}/{q.endpoints_total}",
             value_color=SUCCESS)
        _row(g, "trustworthy", q.endpoints_trustworthy, value_color=SUCCESS)
        noise = q.endpoint_levels.get("noise", 0)
        _row(g, "dead/noise routes", noise, value_color=DIM_GREY if not noise else WARNING)
    if q.duplicates_suppressed:
        _row(g, "duplicates suppressed", q.duplicates_suppressed, value_color=INFO_BLUE)
    if q.secrets_total:
        _row(g, "secrets verified", f"{q.secrets_verified}/{q.secrets_total}",
             value_color=NEON_RED if q.secrets_verified else DIM_GREY)
    if q.replays_total:
        _row(g, "replay stable", f"{q.replays_stable}/{q.replays_total}",
             value_color=SUCCESS)
        if q.replays_anomalous:
            _row(g, "replay anomalies", q.replays_anomalous, value_color=WARNING)
    return g


def render_replay_activity(state: DashboardState) -> Table:
    """Chronological replay activity feed for the dashboard (newest first)."""
    from .workbench import render_replay_timeline
    return render_replay_timeline(state.replay, limit=10)


def render_replay_trust(state: DashboardState) -> Table:
    """Replay stability + anomaly breakdown — how trustworthy the replays are."""
    a = state.replay_analytics
    g = _grid()
    if a.empty:
        g.add_row(f"[{MUTED}]no replays issued yet[/]", "")
        return g
    stab_color = SUCCESS if a.stability_pct >= 70 else WARNING if a.stability_pct >= 40 else NEON_RED
    g.add_row(
        f"[{OFF_WHITE}]stability[/]",
        f"{_bar(a.stability_pct, color=stab_color)} [{stab_color}]{a.stability_pct:.0f}%[/]",
    )
    _row(g, "stable / total", f"{a.stable}/{a.total}", value_color=stab_color)
    _row(g, "anomalous", a.anomalous, value_color=WARNING if a.anomalous else DIM_GREY)
    _row(g, "avg confidence", f"{a.avg_confidence:.0f}", value_color=OFF_WHITE)
    if a.anomaly_counts:
        g.add_row(f"[{DIM_GREY}]anomalies[/]", "")
        for kind, n in sorted(a.anomaly_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            g.add_row(f"[{WARNING}]· {kind}[/]", f"[{WARNING}]{n}[/]")
    return g


def render_attack_surface_map(state: DashboardState):
    """Confidence-heat-mapped host → route-group → endpoint tree."""
    from .graphview import render_graph_tree
    return render_graph_tree(state.surface_graph, max_nodes=40)


def render_endpoint_clusters(state: DashboardState):
    """Endpoints grouped by attack-surface class, confidence-coloured."""
    from .graphview import render_graph_tree
    return render_graph_tree(state.cluster_graph, max_nodes=40)


def render_discovery_stats(state: DashboardState) -> Table:
    d = state.discovery
    g = _grid()
    if d.empty:
        g.add_row(f"[{MUTED}]no recon-tool output yet[/]", "")
        return g
    _row(g, "subdomains", len(d.subdomains))
    _row(g, "urls", len(d.urls))
    _row(g, "total", d.total)
    for tool, n in sorted(d.by_tool.items(), key=lambda kv: kv[1], reverse=True):
        g.add_row(f"[{DIM_GREY}]· {tool}[/]", f"[{INFO_BLUE}]{n}[/]")
    return g


def render_subdomains(state: DashboardState) -> Table:
    subs = sorted(state.discovery.subdomains)[:18]
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(ratio=1)
    if not subs:
        g.add_row(f"[{MUTED}]run 'connector subfinder <domain>'[/]")
        return g
    for s in subs:
        g.add_row(f"[{INFO_BLUE}]›[/] [{OFF_WHITE}]{s}[/]")
    return g


def render_recon_pipeline(state: DashboardState) -> Table:
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(ratio=1)
    recon_tools = ("subfinder", "amass", "assetfinder", "httpx", "katana", "gau", "waybackurls", "ffuf")
    for tool in recon_tools:
        ran = state.discovery.by_tool.get(tool, 0)
        if tool not in state.connectors:
            g.add_row(f"[{MUTED}]○ {tool}[/]")
        elif ran:
            g.add_row(f"[{SUCCESS}]●[/] [{OFF_WHITE}]{tool}[/] [{DIM_GREY}]· {ran}[/]")
        else:
            g.add_row(f"[{DIM_GREY}]◌ {tool} (ready)[/]")
    return g


# ---------------------------------------------------------------------------
# The dashboard app
# ---------------------------------------------------------------------------

_HELP = """[b]commands[/]
  scan <url> [--passive]   recon + analyzers, live
  crawl <url>              discover endpoints only
  connector <name> <url> [k=v]   nuclei/sqlmap/burp + recon:
        subfinder · amass · assetfinder · httpx · katana · gau · waybackurls · ffuf
  replay [#]               list / re-issue recorded requests
  workbench | wb           open replay workbench (ctrl+w)
  findings | intel         refresh & summarize
  notes <text>             append a workspace note
  refresh                  redraw panels
  clear                    clear logs
  help | quit"""


class SpyderDashboard(App):
    """Fullscreen persistent SOC dashboard."""

    CSS = theme.DASHBOARD_CSS
    TITLE = "SPYDER"
    BINDINGS = [
        # Ctrl+C returns straight to the REPL (Textual's default binds ctrl+c to a
        # "Do you want to quit?" confirmation; a priority binding overrides it so a
        # single Ctrl+C cleanly tears the dashboard down — as the launch hint says).
        Binding("ctrl+c", "quit", "Return to console", priority=True, show=False),
        Binding("ctrl+q", "quit", "Return to console", priority=True, show=False),
        ("ctrl+l", "clear_logs", "Clear"),
        ("ctrl+r", "refresh", "Refresh"),
        ("ctrl+w", "workbench", "Workbench"),
    ]

    def __init__(self, config: SpyderConfig, workspace: str = "default", profile: str = "default"):
        super().__init__()
        self.controller = DashboardController(config, workspace, profile)
        self._unsub: Callable[[], None] | None = None

    # --- composition ---
    def compose(self) -> ComposeResult:
        yield Static(id="topbar")
        with Horizontal(id="body"):
            with Vertical(id="left-pane"):
                yield RichLog(id="event-stream", markup=True, highlight=False, wrap=True, auto_scroll=True)
            with VerticalScroll(id="center-pane"):
                yield HudPanel("recon", id="recon-summary")
                yield HudPanel("findings", id="findings-summary")
                yield HudPanel("attack surface", id="attack-surface")
                yield HudPanel("attack-surface map", id="attack-surface-map")
                yield HudPanel("parameters", id="param-analytics")
                yield HudPanel("js intelligence", id="js-intel")
                yield HudPanel("api map", id="api-map")
                yield HudPanel("discovery", id="discovery-stats")
                yield HudPanel("subdomains", id="subdomains")
                yield HudPanel("replay activity", id="replay-activity")
            with VerticalScroll(id="right-pane"):
                yield HudPanel("signal quality", accent=True, id="signal-quality")
                yield HudPanel("endpoint clusters", accent=True, id="endpoint-clusters")
                yield HudPanel("replay trust", accent=True, id="replay-trust")
                yield HudPanel("technologies", accent=True, id="tech-summary")
                yield HudPanel("fingerprints", accent=True, id="fingerprints")
                yield HudPanel("high-interest", accent=True, id="high-interest")
                yield HudPanel("secrets", accent=True, id="secrets")
                yield HudPanel("recon pipeline", accent=True, id="recon-pipeline")
        yield RichLog(id="command-output", markup=True, highlight=False, wrap=True, auto_scroll=True)
        with Horizontal(id="footer-bar"):
            yield Input(
                placeholder="spyder>  scan <url> · crawl <url> · connector <name> <url> · replay <#> · help",
                id="cmd-input",
            )
            yield Static(id="status-bar")

    # --- lifecycle ---
    def on_mount(self) -> None:
        self.query_one("#event-stream", RichLog).border_title = "◢ LIVE EVENT STREAM ◣"
        self.query_one("#command-output", RichLog).border_title = "◢ COMMAND OUTPUT ◣"
        self._unsub = self.controller.events.subscribe(self._on_event)
        self.refresh_panels()
        out = self.query_one("#command-output", RichLog)
        out.write(
            f"[{NEON_RED}]◢ SPYDER ◣[/] recon intelligence OS online · "
            f"workspace [{NEON_RED}]{self.controller.workspace}[/] · type [{OFF_WHITE}]help[/]"
        )
        out.write(f"[{MUTED}]All testing must be authorized. SPYDER maps surface; it does not exploit.[/]")
        self.query_one("#cmd-input", Input).focus()

    def on_unmount(self) -> None:
        if self._unsub:
            self._unsub()
        self.controller.close()

    # --- event stream ---
    def _on_event(self, event) -> None:
        if event.type is EventType.CRAWL_PROGRESS:
            self._update_topbar()  # high-frequency: counter only, no log spam
            return
        log = self.query_one("#event-stream", RichLog)
        color = theme.event_color(event.type.value)
        log.write(f"[{MUTED}]{event.clock}[/] [{color}]●[/] {event.message}")
        self._update_topbar()

    # --- rendering ---
    def refresh_panels(self) -> None:
        state = self.controller.snapshot()
        self.query_one("#recon-summary", HudPanel).update(render_recon_summary(state))
        self.query_one("#findings-summary", HudPanel).update(render_findings_summary(state))
        self.query_one("#attack-surface", HudPanel).update(render_attack_surface(state))
        self.query_one("#attack-surface-map", HudPanel).update(render_attack_surface_map(state))
        self.query_one("#param-analytics", HudPanel).update(render_param_analytics(state))
        self.query_one("#js-intel", HudPanel).update(render_js_intel(state))
        self.query_one("#api-map", HudPanel).update(render_api_map(state))
        self.query_one("#discovery-stats", HudPanel).update(render_discovery_stats(state))
        self.query_one("#subdomains", HudPanel).update(render_subdomains(state))
        self.query_one("#replay-activity", HudPanel).update(render_replay_activity(state))
        self.query_one("#signal-quality", HudPanel).update(render_signal_quality(state))
        self.query_one("#endpoint-clusters", HudPanel).update(render_endpoint_clusters(state))
        self.query_one("#replay-trust", HudPanel).update(render_replay_trust(state))
        self.query_one("#tech-summary", HudPanel).update(render_tech_summary(state))
        self.query_one("#fingerprints", HudPanel).update(render_fingerprints(state))
        self.query_one("#high-interest", HudPanel).update(render_high_interest(state))
        self.query_one("#secrets", HudPanel).update(render_secrets(state))
        self.query_one("#recon-pipeline", HudPanel).update(render_recon_pipeline(state))
        self._update_topbar()
        self._update_status()

    def _update_topbar(self) -> None:
        c = self.controller
        eps = len(c.orch.endpoints())
        fnd = len(c.orch.findings())
        ev = len(c.events.history)
        js = c.orch.js_intel()
        js_routes = len(js.intel.endpoints)
        secrets = len(js.intel.secrets)
        if c.scanning:
            status = f"[{WARNING}]● SCANNING[/]"
        else:
            status = f"[{SUCCESS}]● IDLE[/]"
        self.query_one("#topbar", Static).update(
            f"[b {NEON_RED}]◢ SPYDER ◣[/] [{DIM_GREY}]recon intelligence OS[/]    "
            f"[{DIM_GREY}]ws[/] [{OFF_WHITE}]{c.workspace}[/]   "
            f"[{DIM_GREY}]endpoints[/] [{NEON_RED}]{eps}[/]   "
            f"[{DIM_GREY}]js routes[/] [{NEON_RED}]{js_routes}[/]   "
            f"[{DIM_GREY}]secrets[/] [{NEON_RED}]{secrets}[/]   "
            f"[{DIM_GREY}]findings[/] [{NEON_RED}]{fnd}[/]   "
            f"[{DIM_GREY}]events[/] [{NEON_RED}]{ev}[/]   {status}"
        )

    def _update_status(self) -> None:
        c = self.controller
        mode = "PASSIVE" if c.config.passive_mode else "ACTIVE"
        dot = WARNING if c.scanning else SUCCESS
        self.query_one("#status-bar", Static).update(
            f"[{DIM_GREY}]mode[/] [{OFF_WHITE}]{mode}[/]  "
            f"[{DIM_GREY}]profile[/] [{OFF_WHITE}]{c.profile}[/]  [{dot}]●[/]"
        )

    # --- actions ---
    def action_clear_logs(self) -> None:
        self.query_one("#event-stream", RichLog).clear()
        self.query_one("#command-output", RichLog).clear()

    def action_refresh(self) -> None:
        self.refresh_panels()

    def action_workbench(self) -> None:
        """Open the full-screen replay workbench (request/response analysis)."""
        from .workbench import ReplayWorkbenchScreen
        if self.controller.orch.replay_records():
            self.push_screen(ReplayWorkbenchScreen(self.controller))
        else:
            self.query_one("#command-output", RichLog).write(
                f"[{DIM_GREY}]no replays yet — run 'replay <#>' first[/]"
            )

    # --- command dispatch ---
    async def on_input_submitted(self, message: Input.Submitted) -> None:
        line = message.value.strip()
        self.query_one("#cmd-input", Input).value = ""
        if line:
            await self._dispatch(line)

    async def _dispatch(self, line: str) -> None:
        out = self.query_one("#command-output", RichLog)
        out.write(f"[{NEON_RED}]spyder>[/] {line}")
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("quit", "exit", "q"):
            self.exit()
        elif cmd in ("help", "?"):
            out.write(_HELP)
        elif cmd in ("clear", "cls"):
            self.action_clear_logs()
        elif cmd in ("refresh", "r"):
            self.refresh_panels()
        elif cmd in ("findings", "f", "intel"):
            self.refresh_panels()
            out.write(f"[{SUCCESS}]panels refreshed[/]")
        elif cmd == "notes":
            if args:
                self.controller.orch.paths.append_note(" ".join(args))
                out.write(f"[{SUCCESS}]note saved[/]")
            else:
                out.write(f"[{NEON_RED}]usage:[/] notes <text>")
        elif cmd == "scan":
            if not args:
                out.write(f"[{NEON_RED}]usage:[/] scan <url> [--passive]")
            elif self.controller.scanning:
                out.write(f"[{WARNING}]a scan is already running[/]")
            else:
                passive = "--passive" in args
                self.run_worker(
                    self._do_scan(_normalize_url(args[0]), passive),
                    name="scan", group="recon", exclusive=True,
                )
        elif cmd == "crawl":
            if not args:
                out.write(f"[{NEON_RED}]usage:[/] crawl <url>")
            elif self.controller.scanning:
                out.write(f"[{WARNING}]a scan is already running[/]")
            else:
                self.run_worker(
                    self._do_scan(_normalize_url(args[0]), False, analyzers=False),
                    name="crawl", group="recon", exclusive=True,
                )
        elif cmd in ("connector", "conn"):
            if len(args) < 2:
                avail = ", ".join(self.controller.orch.registry.connectors)
                out.write(f"[{NEON_RED}]usage:[/] connector <name> <url> [k=v]   [{DIM_GREY}]({avail})[/]")
            else:
                opts = {}
                for kv in args[2:]:
                    k, _, v = kv.partition("=")
                    opts[k] = True if v == "" else v
                self.run_worker(
                    self._do_connector(args[0], _normalize_url(args[1]), opts),
                    name="connector", group="orchestration",
                )
        elif cmd == "replay":
            if args and args[0].isdigit():
                self.run_worker(self._do_replay(int(args[0])), name="replay", group="replay")
            else:
                self._list_replay()
        elif cmd in ("workbench", "wb"):
            self.action_workbench()
        else:
            out.write(f"[{NEON_RED}]unknown command:[/] {cmd}  [{DIM_GREY}](try 'help')[/]")

    # --- workers ---
    async def _do_scan(self, url: str, passive: bool, analyzers: bool = True) -> None:
        c = self.controller
        out = self.query_one("#command-output", RichLog)
        c.scanning = True
        if passive:
            c.config.passive_mode = True
        self._update_topbar()
        self._update_status()
        try:
            target = parse_target(url)
            endpoints = await c.orch.recon(target)
            if analyzers:
                await c.orch.run_analyzers(endpoints)
            out.write(
                f"[{SUCCESS}]complete[/] · {len(endpoints)} endpoints · "
                f"{len(c.orch.findings())} findings"
            )
        except Exception as exc:
            out.write(f"[{NEON_RED}]error:[/] {exc}")
            c.events.emit(EventType.ERROR, f"scan failed: {exc}")
        finally:
            c.scanning = False
            self.refresh_panels()

    async def _do_connector(self, name: str, url: str, opts: dict) -> None:
        c = self.controller
        out = self.query_one("#command-output", RichLog)
        try:
            findings = await c.orch.run_connector(name, url, opts)
            out.write(f"[{SUCCESS}]{name}[/] · {len(findings)} findings")
        except Exception as exc:
            out.write(f"[{NEON_RED}]connector error:[/] {exc}")
            c.events.emit(EventType.ERROR, f"connector failed: {exc}")
        finally:
            self.refresh_panels()

    async def _do_replay(self, idx: int) -> None:
        c = self.controller
        out = self.query_one("#command-output", RichLog)
        try:
            rec = await c.orch.replay(idx)
            badge = theme.confidence_badge(rec.confidence_level, rec.confidence_score)
            out.write(f"[{INFO_BLUE}]replay #{idx}[/] {rec.method} {rec.url}  {badge}")
            out.write(
                f"  status {rec.original_status} → [b]{rec.replayed_status}[/] · "
                f"sim {rec.similarity} · Δlen {rec.length_delta:+d} · {rec.timing_ms:.0f}ms"
            )
            if rec.anomalies:
                out.write(f"  [{WARNING}]anomalies:[/] {', '.join(rec.anomalies)}")
            out.write(f"  [{DIM_GREY}]notable:[/] {', '.join(rec.notable) or 'none'}")
        except Exception as exc:
            out.write(f"[{NEON_RED}]replay error:[/] {exc}")
        finally:
            self.refresh_panels()

    def _list_replay(self) -> None:
        out = self.query_one("#command-output", RichLog)
        txns = self.controller.orch.last_transactions
        if not txns:
            out.write(f"[{DIM_GREY}]no recorded transactions — run a scan first[/]")
            return
        out.write(f"[{DIM_GREY}]replay buffer ({len(txns)}):[/]")
        for i, t in enumerate(txns[:25]):
            out.write(
                f"  [{NEON_RED}]{i}[/] [{OFF_WHITE}]{t.method}[/] "
                f"[{DIM_GREY}]{t.status or '—'}[/] {_short_url(t.url)}"
            )
        out.write(f"[{DIM_GREY}]replay <#> to re-issue[/]")


def _normalize_url(raw: str) -> str:
    from ..core.models import normalize_url
    return normalize_url(raw)


# ---------------------------------------------------------------------------
# Launch helpers
# ---------------------------------------------------------------------------


def build_dashboard(config: SpyderConfig, workspace: str = "default", profile: str = "default") -> SpyderDashboard:
    return SpyderDashboard(config, workspace=workspace, profile=profile)


def run_dashboard(config: SpyderConfig, workspace: str = "default", profile: str = "default") -> None:
    """Blocking launch (own event loop) — used by the one-shot CLI."""
    build_dashboard(config, workspace, profile).run()


async def run_dashboard_async(config: SpyderConfig, workspace: str = "default", profile: str = "default") -> None:
    """Async launch — used from inside the REPL's running event loop.

    Textual's ``run_async`` mutates the *current* event loop's task factory
    (``eager_task_factory``) and does not restore it. Since we run on the REPL's
    own loop, we snapshot and restore the factory so prompt_toolkit keeps behaving
    exactly as before the dashboard was launched.
    """
    import asyncio

    loop = asyncio.get_running_loop()
    prev_factory = loop.get_task_factory()
    try:
        await build_dashboard(config, workspace, profile).run_async()
    finally:
        loop.set_task_factory(prev_factory)
