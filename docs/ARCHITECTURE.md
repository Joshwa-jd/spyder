# SPYDER — Architecture Reference

## Package Layout

```
spyder/                  ← the importable Python package
├── __main__.py          ← the ONE entry point (argparse + dispatch, lazy imports)
│
├── cli/                 ← documented CLI import surface (aliases, not copies)
│   ├── parser.py        ← build_parser
│   ├── dispatcher.py    ← main
│   ├── shell.py         ← run_console, ShellContext
│   ├── banner.py        ← render_banner
│   ├── renderer.py      ← findings_table, stats_panel, …
│   ├── progress.py      ← info / ok / err / warn
│   ├── completion.py    ← build_completer
│   └── validator.py     ← parse_target, normalize_url
│
├── core/                ← foundational, no-I/O primitives
│   ├── config.py        ← SpyderConfig (pydantic-settings + YAML)
│   ├── events.py        ← EventBus (synchronous fan-out pub/sub)
│   ├── models.py        ← Endpoint, Finding, Target, Parameter (pydantic)
│   ├── pipeline.py      ← PipelineStage + CommandPipeline (named lifecycle)
│   └── orchestrator.py  ← Orchestrator (workflow engine, wires subsystems)
│
├── http/                ← proxy-aware async HTTP client
│   └── client.py        ← HTTPClient + Transaction (replayable records)
│
├── crawler/             ← endpoint discovery
│   ├── engine.py        ← Crawler (BFS, scope-enforced, robots/sitemap)
│   └── params.py        ← ParameterProber (reflection detection, benign markers)
│
├── connectors/          ← external-tool bridges (subprocess orchestration)
│   ├── base.py          ← ExternalToolConnector (exec + stream + event emit)
│   ├── nuclei.py        ← NucleiConnector
│   ├── sqlmap.py        ← SqlmapConnector (requires authorized=True)
│   ├── burp.py          ← BurpConnector (proxy mode + REST API mode)
│   └── recon.py         ← subfinder, amass, assetfinder, httpx, katana, gau, …
│
├── analysis/            ← read-only intelligence derivation
│   ├── intel.py         ← EndpointIntel, AttackSurface, TechSummary
│   ├── diff.py          ← ResponseDiff, similarity, reflection detection
│   ├── replay.py        ← ReplayRecord, ReplayHistory, ReplayAnalytics
│   ├── fingerprint.py   ← passive tech/WAF/DBMS fingerprinting
│   ├── jsintel.py       ← JsReconEngine (JS mining, secrets, API routes)
│   ├── graph.py         ← Graph, build_attack_surface_graph, …
│   └── discovery.py     ← DiscoverySummary (aggregates recon-tool output)
│
├── validation/          ← trust & confidence scoring (deterministic, no I/O)
│   ├── confidence.py    ← Confidence, Signal, ConfidenceLevel
│   ├── endpoints.py     ← ValidatedEndpoint, deduplicate_endpoints
│   ├── entropy.py       ← shannon_entropy, looks_random
│   ├── fingerprint.py   ← TechConfidence, validate_technologies
│   ├── normalize.py     ← normalize_url, route_template, dedup_key
│   ├── replay.py        ← ReplayConfidence, replay_confidence
│   ├── secrets.py       ← SecretValidation, validate_secret_value
│   └── summary.py       ← SignalQuality, signal_quality
│
├── workspace/           ← persistence layer
│   ├── manager.py       ← WorkspaceManager (SQLite: endpoints, findings, …)
│   └── layout.py        ← WorkspacePaths (filesystem: evidence, timeline)
│
├── reporting/           ← output rendering
│   ├── engine.py        ← ReportEngine (HTML, JSON, Markdown, PDF)
│   ├── graphsvg.py      ← deterministic SVG renderer for intelligence graphs
│   └── templates/       ← Jinja2 templates (report.html.j2, report.md.j2)
│
├── plugins/             ← extensibility contracts
│   └── framework.py     ← Plugin ABC hierarchy + PluginRegistry
│
├── ui/                  ← presentation layer (Rich + Textual)
│   ├── theme.py         ← single source of truth for the cyberpunk palette
│   ├── shell.py         ← interactive REPL (prompt_toolkit)
│   ├── commands.py      ← Command + CommandRegistry (modular dispatch)
│   ├── builtins.py      ← built-in console commands
│   ├── display.py       ← Rich components (splash, tables, panels)
│   ├── dashboard.py     ← Textual fullscreen SOC dashboard
│   ├── workbench.py     ← Textual replay analysis screen
│   └── graphview.py     ← Rich Tree renderer for intelligence graphs
│
└── utils/
    ├── logging.py       ← Rich-backed structured logging
    └── scope.py         ← ScopeGuard + async RateLimiter
```

## Dependency Rules

```
core  ←── (no internal deps — imported by everyone)
http  ←── core
crawler ←── core, http
connectors ←── core, plugins
analysis ←── core, http, validation
validation ←── core
workspace ←── core
reporting ←── core, analysis, ui.theme
plugins ←── core
ui ←── core, analysis, validation, workspace, reporting, plugins
orchestrator (core/) ←── all of the above
```

`spyder.cli` sits above everything as a naming facade: every symbol it exports is
an alias of the single implementation in `spyder.ui` / `spyder.__main__`, so it
adds no second code path that could drift.

## Command Lifecycle

Every command — typed in the REPL, passed on the CLI, or issued from the
dashboard command bar — travels the same named stages
(`spyder.core.pipeline.PipelineStage`):

```
parse → validate → permission → workspace → execute → plugins → result → database → render
```

`CommandPipeline` is a thin facade over `Orchestrator` so all three front-ends
share one execution path rather than each reimplementing dispatch.

## Connector Lifecycle

Every connector exposes the same six stages regardless of how it reaches its
tool (subprocess, REST API, stdin stream):

```
initialize → validate → execute → parse → cleanup → status
```

`ConnectorPlugin.invoke()` runs `initialize → validate → execute → cleanup` in
order and is what the orchestrator drives; `cleanup()` always runs, including
when validation fails. `execute()` delegates to the connector's `run()` by
default. See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md).

## Terminal Ownership

Screen control has exactly one owner, `spyder.ui.terminal`. It is the only module
permitted to emit cursor-movement, alternate-screen, or clearing escape
sequences; `restore()` and `clear()` are the only primitives. Banner *content*
has one owner too, `spyder.ui.banner`. This is why startup, `clear`, `restart`,
workspace switching, and dashboard exit all leave the terminal in an identical,
predictable state.

## Startup Cost

`spyder/__main__.py` imports only `argparse` and `spyder.__version__` at module
scope; every subsystem is imported inside the handler that needs it. `--help`,
`--version`, and argparse errors therefore never construct the orchestrator,
HTTP stack, or Rich/Textual UI. Keep it that way — a module-level import of a
heavy subsystem here is a ~10× regression on the most frequently run commands
(measured: 700 ms → 66 ms).

## Key Design Decisions

- **EventBus** — synchronous, non-blocking fan-out. Subscribers must not raise.
- **Scope enforcement** — `ScopeGuard` blocks every outgoing URL at the crawler and connector level.
- **No exploitation logic** — connectors shell out to user-installed tools; SPYDER owns orchestration, not payloads.
- **No fabricated results** — a missing tool is an error, never an empty "clean" result.
- **Validation layer** — every discovery gets a `Confidence` score built from named `Signal` contributions — explainable, deterministic, testable.
- **Workspace isolation** — SQLite + filesystem layout keeps each engagement self-contained and resumable.
- **Secrets are redacted at extraction** — the unredacted value is analysed in memory for entropy scoring and never written to the database, reports, or logs.
- **Untrusted text is escaped** — finding fields can carry attacker-influenced content, so HTML reports autoescape (including `.html.j2`) and filesystem labels pass through `safe_slug()`.
