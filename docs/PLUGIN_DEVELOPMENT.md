# Writing SPYDER Plugins

A plugin is a single `.py` file in a plugin directory. SPYDER discovers it at
startup, instantiates it, and wires it into the pipeline. No registration file,
no entry point, no rebuild.

## Where plugins go

SPYDER scans the directories in `config.plugin_dirs`. By default that is exactly
one directory:

```
~/.local/share/spyder/plugins/          (or $SPYDER_HOME/plugins)
```

**The repository's own `plugins/` directory is not scanned automatically** — it
holds the shipped example, and the working directory you happen to launch from
is not a trustworthy place to load code from. Pick one of these three:

```bash
# 1. Copy it into the default directory (simplest)
cp plugins/reflection_review.py ~/.local/share/spyder/plugins/

# 2. Point at a directory with an environment variable
SPYDER_PLUGIN_DIRS='["/path/to/my/plugins"]' spyder

# 3. Put it in a YAML profile (best for a team or an engagement)
cat > mine.yaml <<'YAML'
plugin_dirs:
  - /path/to/my/plugins
YAML
spyder --profile mine.yaml
```

The default directory is always scanned in addition to anything you configure.

Confirm what SPYDER sees — this prints both the loaded plugins and every
directory that was scanned:

```bash
spyder plugins
```

If your plugin isn't listed, either it's in a directory that isn't scanned, or it
raised on import. Import errors are logged, not swallowed silently:

```bash
tail ~/.local/share/spyder/logs/spyder.log
```

Files beginning with `_` are skipped.

## Your first plugin

```python
# ~/.local/share/spyder/plugins/long_query.py
"""Flag endpoints carrying unusually long query parameters."""
from __future__ import annotations

from typing import Any

from spyder.core.models import Endpoint, Finding, Severity
from spyder.plugins.framework import AnalyzerPlugin


class LongQueryAnalyzer(AnalyzerPlugin):
    name = "long-query"        # must be unique — it is the registry key
    version = "1.0.0"

    async def analyze(
        self, endpoints: list[Endpoint], context: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for ep in endpoints:
            for p in ep.params:
                if len(p.name) > 40:
                    findings.append(
                        Finding(
                            title="Unusually long parameter name",
                            severity=Severity.INFO,
                            endpoint=ep.url,
                            description=f"Parameter {p.name!r} is {len(p.name)} chars.",
                            evidence={"param": p.name, "length": len(p.name)},
                            source="SPYDER:plugin:long-query",
                        )
                    )
        return findings
```

Restart SPYDER and run `plugins` — `long-query` appears under analyzers, and
`scan` will now call it.

## Discovery rules

SPYDER loads a plugin file two ways, and both can apply to the same file:

1. **Class discovery** — every non-abstract `Plugin` subclass in the module is
   instantiated with no arguments and registered. Keep `__init__` argument-free,
   or use `register()` instead.
2. **`register(registry)`** — if the module defines a top-level `register`
   function, SPYDER calls it with the `PluginRegistry`. Use this when you need
   constructor arguments or want to register several instances:

   ```python
   def register(registry):
       registry.add(ThresholdAnalyzer(threshold=40))
       registry.add(ThresholdAnalyzer(threshold=80))
   ```

A plugin that raises during import or instantiation is logged and skipped; it
never takes the framework down with it.

## Plugin contracts

| Base class | Method | Returns | Called when |
|---|---|---|---|
| `AnalyzerPlugin` | `async analyze(endpoints, context)` | `list[Finding]` | after every crawl |
| `ReconPlugin` | `async recon(endpoints, context)` | `list[Finding]` | to expand the inventory |
| `ConnectorPlugin` | `async run(target, options)` | `list[Finding]` | `connector <name>` |
| `ReporterPlugin` | `render(findings, context)` | `str` | custom export format |
| `ReplayPlugin` | `async on_replay(context)` | `None` | after a replay |
| `ReplayAnalyzerPlugin` | `async analyze_replay(record, context)` | `list[Finding]` | after a replay |
| `ReplayVisualizationPlugin` | `visualize_replay(history, context)` | renderable | workbench render |
| `DashboardWidgetPlugin` | `render(state, context)` | Rich renderable | each dashboard refresh |
| `VisualizationPlugin` | `visualize(state, context)` | artifact | on demand |

`AnalyzerPlugin` vs `ReconPlugin` is about intent: recon plugins *expand* what is
known about the attack surface, analyzers *judge* what is already known.

`DashboardWidgetPlugin.render` runs on every refresh — keep it cheap and free of
side effects.

## Writing a connector

Connectors bridge to external tools. Subclass `ExternalToolConnector` and you
inherit subprocess plumbing, PATH checking, timeouts, and event streaming:

```python
from typing import Any

from spyder.connectors.base import ExternalToolConnector
from spyder.core.models import Finding, Severity


class WhatWebConnector(ExternalToolConnector):
    name = "whatweb"
    version = "1.0.0"
    binary = "whatweb"          # checked on PATH by validate()

    async def run(self, target: str, options: dict[str, Any]) -> list[Finding]:
        result = await self._exec(["--log-json=-", target], timeout=120.0)
        if result.returncode != 0:
            return []
        return self.parse(self._to_findings(result.stdout))

    def _to_findings(self, stdout: str) -> list[Finding]:
        return [
            self._finding(
                title="whatweb fingerprint",
                severity=Severity.INFO,
                endpoint=line.split()[0],
                description=line,
            )
            for line in stdout.splitlines() if line.strip()
        ]
```

### The six-stage lifecycle

Every connector exposes the same stages regardless of transport:

| Stage | Purpose | Default behaviour |
|---|---|---|
| `initialize(options)` | reset per-run state | stores options, calls `on_initialize()` |
| `validate(target, options)` | pre-flight checks | non-empty target; binary on PATH |
| `execute(target, options)` | run the tool | delegates to your `run()` |
| `parse(raw)` | normalize output | passes through a `list[Finding]` |
| `cleanup()` | release resources | calls `on_cleanup()` |
| `status()` | report readiness | name, version, availability, binary path |

`invoke()` runs `initialize → validate → execute → cleanup` and is what the
orchestrator calls. `cleanup()` always runs, including when validation fails.
Override `on_initialize()` / `on_cleanup()` for setup and teardown rather than
overriding the stages themselves.

Failed validation raises `ConnectorError`, surfaced to the operator as a clean
message. Import it from either location — they are the same class:

```python
from spyder.connectors.base import ConnectorError      # or
from spyder.plugins.framework import ConnectorError
```

### Subprocess helpers

```python
result = await self._exec(["-flag", target], timeout=600.0)   # buffered
code = await self._stream(["-flag", target], on_line=self._on_line)  # live
code = await self._stream([], on_line=cb, input_data=f"{target}\n")  # via stdin
```

Both call `create_subprocess_exec` with an argument list — never a shell string.
**Never build a command by interpolating a target into a string and never pass
`shell=True`.** Targets are attacker-influenced input.

## Rules for plugins

These are enforced in review:

- **Never fabricate findings.** A missing tool, a timeout, or an unparseable
  response is an error or an empty list — never an invented result. Analysts
  make decisions from this output.
- **Stay in scope.** Do not reach beyond the target the operator supplied.
- **No exploitation.** SPYDER maps and analyses; it does not exploit. Plugins
  that add payloads, attack sequences, or WAF/scope evasion will be rejected.
- **Redact secrets.** If you detect a credential, store a redacted form. See
  `spyder/analysis/jsintel.py` for the pattern.
- **Set `source`.** Use `SPYDER:plugin:<name>` so findings are attributable.
- **Be deterministic where you can.** Same input, same findings — it makes your
  plugin testable and your reports diffable.
- **Fail loudly, not fatally.** Raise a clear exception; the registry isolates
  you from the rest of the run.

## Testing a plugin

Plugins are plain classes — test them directly, no framework needed:

```python
import pytest
from spyder.core.models import Endpoint, HTTPMethod, Parameter, ParamLocation
from long_query import LongQueryAnalyzer


@pytest.mark.asyncio
async def test_flags_long_parameter_names():
    ep = Endpoint(
        url="https://example.com/x",
        method=HTTPMethod.GET,
        params=[Parameter(name="a" * 50, location=ParamLocation.QUERY)],
    )
    findings = await LongQueryAnalyzer().analyze([ep], {})
    assert len(findings) == 1
    assert findings[0].evidence["length"] == 50
```

Run the framework's own suite before opening a PR:

```bash
pytest && ruff check . && mypy spyder/
```

## Reference

- Contracts: `spyder/plugins/framework.py`
- Connector base: `spyder/connectors/base.py`
- Worked examples: `spyder/connectors/recon.py`, `plugins/reflection_review.py`
- Models: `spyder/core/models.py` (`Finding`, `Endpoint`, `Severity`)
