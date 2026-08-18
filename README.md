<div align="center">

# ◢ SPYDER ◣

**Modular red-team workflow orchestration platform**

*recon · discovery · analysis · replay · report*

---

[![CI](https://github.com/joshwa-n/spyder/actions/workflows/ci.yml/badge.svg)](https://github.com/joshwa-n/spyder/actions/workflows/ci.yml)
[![CodeQL](https://github.com/joshwa-n/spyder/actions/workflows/codeql.yml/badge.svg)](https://github.com/joshwa-n/spyder/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/Python-3.12%2B-red?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0.0-red?style=flat-square)

> **All testing must be authorized.** SPYDER maps attack surface — it does not exploit anything.

</div>

---

## What is SPYDER?

SPYDER is a modular, async-native recon platform for authorized bug bounty and
red-team engagements. It orchestrates the tools you already have — `subfinder`,
`nuclei`, `sqlmap`, `katana`, `ffuf`, Burp Suite — and wires them into one
event-driven pipeline with a live Textual dashboard, an interactive REPL,
persistent workspaces, and publishable reports.

**The problem it solves:** a real engagement means running eight tools, each with
its own output format, then reconciling them by hand into something you can hand
to a client. SPYDER runs them under one workflow, normalizes every result into a
common `Finding` model, deduplicates across sources, scores each discovery with
an explainable confidence rating, and exports the lot as HTML, JSON, Markdown, or
PDF.

**What it deliberately does not do:** exploit anything. No payloads, no attack
sequences, no WAF or scope evasion. That boundary is what makes it defensible to
run inside a client's network, and it is enforced in code review.

### Design commitments

- **No fabricated results.** A missing tool is an error, never an empty "clean"
  result. Analysts make decisions from this output.
- **Explainable confidence.** Every discovery carries a score built from named
  signals — you can see *why* SPYDER trusts something.
- **One owner per concern.** One banner implementation, one terminal-control
  module, one entry point. The console behaves the same way every time.
- **Secrets stay redacted.** Detected credentials are scored in memory and only
  the redacted form ever reaches disk.

---

## Features

| | |
|---|---|
| **Crawl & discover** | BFS crawler, form parsing, JS mining, robots/sitemap |
| **Parameter intelligence** | Discover and probe parameters with benign reflection markers |
| **Passive fingerprinting** | Tech stack, WAF, and DBMS inferred from response signatures |
| **JS recon** | Mine API routes, hidden endpoints, and secret patterns from served JavaScript |
| **Tool orchestration** | subfinder, amass, assetfinder, httpx, katana, gau, waybackurls, ffuf, nuclei, sqlmap, Burp REST API |
| **Replay workbench** | Re-issue recorded requests, diff responses, tag and annotate |
| **Confidence validation** | Every discovery gets a scored, explainable trust rating |
| **Workspace persistence** | SQLite-backed, per-engagement isolation with timeline logs |
| **Reporting** | HTML, JSON, Markdown, PDF with embedded intelligence graphs |
| **Live dashboard** | Full-screen Textual SOC view streaming pipeline events |
| **Plugin framework** | Nine extension contracts, directory-based discovery, no rebuild |

---

## Installation

```bash
git clone https://github.com/joshwa-n/spyder.git
cd spyder
python3 -m venv venv && source venv/bin/activate
pip install -e .

spyder --version        # SPYDER 1.0.0
```

Optional extras: `pip install -e ".[pdf]"` (PDF export), `".[fast]"` (uvloop +
orjson), `".[dev]"` (test tooling).

External tools are **optional** and installed by you — SPYDER runs fine with none
of them, and a missing binary produces a clear error rather than a fake result.

Full instructions, including the external-tool matrix and troubleshooting:
**[docs/INSTALL.md](docs/INSTALL.md)**

---

## Quick Start

```bash
spyder                                        # interactive console
```

```
spyder(default)> workspace new acme
[+] created workspace acme
spyder(acme)> scan https://target.example.com
spyder(acme)> connector nuclei https://target.example.com
spyder(acme)> findings
spyder(acme)> report html
[+] report written: ~/.local/share/spyder/reports/acme-20260727-143022.html
```

Or one-shot, for scripts and CI:

```bash
spyder -w acme scan -u https://target.example.com
spyder -w acme connector nuclei -u https://target.example.com
spyder -w acme report --format json
```

Ten-minute walkthrough: **[docs/QUICKSTART.md](docs/QUICKSTART.md)**

---

## Screenshots

`spyder --help` — every command, one entry point:

```
usage: spyder [-h] [--version] [-w WORKSPACE] [--profile PATH] [--no-anim]
              {scan,crawl,connector,report,findings,workspaces,plugins,dashboard} ...

SPYDER — red-team workflow orchestration (authorized testing only)
Run without arguments to launch the interactive console.

positional arguments:
    scan                Recon + analyzers in one pass
    crawl               Crawl & discover endpoints only
    connector           Run an external-tool connector
    report              Export findings to a report file
    findings            List findings recorded in a workspace
    workspaces          List all workspaces
    plugins             List loaded plugins & connectors
    dashboard           Launch the persistent Textual SOC dashboard
```

`spyder plugins` — what is loaded, and where SPYDER looked:

```
Loaded plugins & connectors
  analyzers: —
  reporters: —
  connectors: nuclei, sqlmap, burp, subfinder, amass, assetfinder, httpx,
              katana, gau, waybackurls, ffuf
  recon: —
Plugin directories scanned
  /home/analyst/.local/share/spyder/plugins
```

The interactive console shows the active workspace in the prompt, so findings
never land somewhere you did not intend:

```
spyder(acme)> findings
SPYDER · Findings
┏━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Sev        ┃    # ┃ Title                ┃ Endpoint         ┃ Source         ┃
┡━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ MEDIUM     │    1 │ Secrets in JavaScript│ https://target…  │ SPYDER         │
│ INFO       │    2 │ Passive fingerprint  │ https://target…  │ SPYDER         │
└────────────┴──────┴──────────────────────┴──────────────────┴────────────────┘
```

> Terminal captures are real output from v1.0.0. Image screenshots of the
> Textual dashboard and replay workbench are tracked in the release checklist.

---

## Example workflows

**Passive-only reconnaissance** — no active probing, for scope-sensitive targets:

```bash
spyder --profile configs/passive.yaml -w acme scan -u https://target.example.com
spyder -w acme report --format md
```

**Through Burp Suite** — route everything via an intercepting proxy:

```
spyder(acme)> set proxy http://127.0.0.1:8080
spyder(acme)> scan https://target.example.com
```

**Subdomain sweep, then probe what is live:**

```bash
spyder -w acme connector subfinder -u target.example.com
spyder -w acme connector httpx     -u target.example.com
spyder -w acme connector nuclei    -u https://target.example.com
spyder -w acme report --format html --target target.example.com
```

**Isolated engagement data** — keep a client's data off your home directory:

```bash
export SPYDER_HOME=/engagements/acme
spyder -w acme scan -u https://target.example.com
```

**Scheduled re-scan** — findings deduplicate, so re-running updates rather than
piling up:

```bash
#!/usr/bin/env bash
set -euo pipefail
spyder -w acme scan -u https://target.example.com
spyder -w acme report --format json --target target.example.com
```

**Resume, days later:**

```bash
spyder -w acme          # everything is still there
```

---

## Commands

Every console command has a one-shot CLI form. Both share one implementation.

### Console

```
scan <url> [--passive]            Recon + analyzers
crawl <url>                       Endpoint discovery only
connector <name> <url> [k=v]      Run subfinder / nuclei / sqlmap / burp / …
replay [#]                        List or re-issue recorded requests
findings                          List findings in the current workspace
report [html|json|md|pdf]         Export findings
workspace [list|use <n>|new <n>]  Manage workspaces
history                           Show scan history for this workspace
dashboard                         Launch the Textual SOC dashboard
set <key> <value>                 Change a runtime setting (proxy, passive, rate)
plugins                           List loaded plugins & connectors
clear                             Clear the screen
restart                           Restart the session in place
help [command]                    Show help
exit                              Quit
```

`help <command>` gives a full man-page-style entry with usage, arguments,
examples, related commands, and exit codes.

### CLI

```bash
spyder scan       -u <url> [-w WS] [--scope HOST…] [--passive] [--proxy URL]
spyder crawl      -u <url> [-w WS] [--scope HOST…]
spyder connector  <name> -u <url> [--opt K=V …] [--authorized]
spyder findings   [-w WS]
spyder report     [--format html|json|md|pdf] [--target LABEL] [-w WS]
spyder workspaces
spyder plugins
spyder dashboard  [-w WS]
```

Global flags (`-w`, `--profile`, `--no-anim`) work before or after the
subcommand. Exit codes: **0** success · **1** error · **2** bad arguments ·
**130** interrupted.

Inside the **dashboard** you also get a live command bar plus the **replay
workbench** (`Ctrl+W`) for request/response diffing, tagging, and annotation.
`Ctrl+C` or `Ctrl+Q` returns to the console with the terminal intact.

---

## Architecture

```
SPYDER/
├── spyder/              ← Python package
│   ├── __main__.py      ← the one entry point (argparse + dispatch)
│   ├── cli/             ← documented CLI import surface
│   ├── core/            ← config, events, models, pipeline, orchestrator
│   ├── http/            ← async HTTP client + transaction recording
│   ├── crawler/         ← BFS crawler + parameter prober
│   ├── connectors/      ← external tool bridges
│   ├── analysis/        ← intel, diff, replay, fingerprint, JS, graph
│   ├── validation/      ← confidence scoring (deterministic, testable)
│   ├── workspace/       ← SQLite persistence + filesystem layout
│   ├── reporting/       ← HTML/JSON/MD/PDF engine + Jinja2 templates
│   ├── plugins/         ← plugin framework & registry
│   └── ui/              ← Textual dashboard, REPL, Rich components
├── configs/             ← YAML profiles
├── docs/                ← install, quickstart, architecture, plugins
├── plugins/             ← example plugin
└── tests/               ← 415 tests
```

Every command — REPL, CLI, or dashboard — travels one named pipeline:

```
parse → validate → permission → workspace → execute → plugins → result → database → render
```

Every connector exposes one lifecycle regardless of transport:

```
initialize → validate → execute → parse → cleanup → status
```

Dependency rules, design decisions, and the terminal-ownership model:
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**

---

## Plugin system

Drop a `.py` file into your plugin directory — SPYDER discovers it at startup.
No registration file, no rebuild.

```python
# ~/.local/share/spyder/plugins/my_analyzer.py
from typing import Any

from spyder.core.models import Endpoint, Finding, Severity
from spyder.plugins.framework import AnalyzerPlugin


class MyAnalyzer(AnalyzerPlugin):
    name = "my-analyzer"
    version = "1.0.0"

    async def analyze(
        self, endpoints: list[Endpoint], context: dict[str, Any]
    ) -> list[Finding]:
        ...
```

```bash
spyder plugins      # confirms it loaded, and names every directory scanned
```

Nine contracts are available: `AnalyzerPlugin`, `ConnectorPlugin`,
`ReconPlugin`, `ReporterPlugin`, `ReplayPlugin`, `ReplayAnalyzerPlugin`,
`ReplayVisualizationPlugin`, `DashboardWidgetPlugin`, `VisualizationPlugin`.

Full guide, including writing connectors and the rules plugins must follow:
**[docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md)**

---

## Configuration

```yaml
# configs/default.yaml — load with --profile configs/default.yaml
passive_mode: false
http:
  timeout: 20.0
  max_connections: 50
  proxy: null          # "http://127.0.0.1:8080" for Burp
crawl:
  max_depth: 3
  max_pages: 500
  concurrency: 10
plugin_dirs:
  - /path/to/my/plugins
```

Environment overrides: `SPYDER_PASSIVE_MODE=true`,
`SPYDER_HTTP__PROXY=http://…`, `SPYDER_HOME=/engagements/acme`.

Data lives in `~/.local/share/spyder/` (or `$SPYDER_HOME`): database,
workspaces, reports, logs, plugins.

---

## Development

```bash
pip install -e ".[dev]"
pytest                 # 415 tests, ~13 min
pytest -m "not pty"    # 388 of them, ~1 min — skips the terminal tests
ruff check .
mypy spyder/
```

CI runs exactly these on Python 3.12 and 3.13, plus a packaging job that
installs the built wheel into a clean environment and asserts all three entry
points report identical versions.

---

## Roadmap

Post-1.0 direction. Nothing here is promised on a date, and none of it will
cross the no-exploitation line.

**1.1 — workspace management**
- `workspace delete` / `export` / `import` / `stats` as first-class commands
- Diffing two scans of the same target: what changed since last week?

**1.2 — reporting**
- Custom report templates without forking
- Executive-summary section with trend data across scans

**1.3 — orchestration**
- Declarative scan profiles: one YAML describing a whole multi-tool workflow
- Parallel connector execution with per-tool concurrency limits

**Under consideration**
- Distributable plugin packages (`pip install spyder-plugin-x`)
- macOS as a supported, CI-tested platform
- Structured JSONL event export for SIEM ingestion

Have an opinion? Open a
[feature request](https://github.com/joshwa-n/spyder/issues/new?template=feature_request.yml).

---

## FAQ

**Is SPYDER a scanner?**
No. It is an orchestration and analysis layer. It crawls, discovers, and analyses
passively itself, and it runs *your* scanners for the rest.

**Does it exploit anything?**
No, by design. No payloads, no attack sequences, no WAF or scope evasion. PRs
adding them are rejected regardless of quality.

**Do I need all those external tools?**
No. SPYDER works with none installed. Each connector is optional and reports
clearly when its binary is missing. `spyder plugins` shows what is available.

**Where does my data go?**
`~/.local/share/spyder/` by default, or `$SPYDER_HOME`. Nothing is sent anywhere.
SPYDER has no telemetry and makes no network requests except to the target you
name.

**Can I run it against a target I do not own?**
No. Unauthorized testing is illegal in most jurisdictions. This is your
responsibility, not the tool's.

**How do I keep engagements separate?**
Workspaces isolate findings, history, and evidence within one data directory.
For stronger separation, give each client its own `SPYDER_HOME`.

**Will re-scanning duplicate my findings?**
No. Findings are identified by a fingerprint (source + severity + title +
endpoint) and re-running updates the stored copy in place.

**Does it work on Windows?**
No. The connectors assume POSIX tooling. Linux is supported; macOS likely works
but is not CI-tested.

**Why is it "spyder-recon" on PyPI?**
`spyder` is taken by the Python IDE. The command is still `spyder`.

**Something is not working.**
Check `$SPYDER_HOME/logs/spyder.log`, re-run with `--debug` for a full
traceback, and see the troubleshooting section in
[docs/INSTALL.md](docs/INSTALL.md).

---

## Contributing

Contributions are welcome — especially connectors, analysis improvements, and
documentation. Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** first,
particularly the scope posture: it tells you in thirty seconds whether your idea
will be accepted.

- 🐛 [Report a bug](https://github.com/joshwa-n/spyder/issues/new?template=bug_report.yml)
- ✨ [Request a feature](https://github.com/joshwa-n/spyder/issues/new?template=feature_request.yml)
- 🔒 [Report a vulnerability privately](https://github.com/joshwa-n/spyder/security/advisories/new) — never in a public issue
- 📖 [Write a plugin](docs/PLUGIN_DEVELOPMENT.md)

All participants are bound by the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Legal

SPYDER is a reconnaissance tool for **authorized** security testing only.
Unauthorized use against systems you do not have explicit written permission to
test is illegal and unethical. The authors assume no responsibility for misuse.

MIT License — see [LICENSE](LICENSE).
