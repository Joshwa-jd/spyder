# Migration Notes

## 0.1.0 → 1.0.0

**There are no breaking changes.** Upgrade in place:

```bash
cd spyder && git pull && pip install -e .
spyder --version        # SPYDER 1.0.0
```

Your workspaces, findings, history, reports, and plugins carry over untouched.

### Your database migrates itself

`WorkspaceManager` brings an older `spyder.sqlite` up to the current schema the
first time it opens it. Nothing to run by hand. The migration:

- adds the `findings.fingerprint` column and backfills it from stored records
- collapses pre-existing duplicate findings, keeping the most recent of each
- adds a unique index so a re-scan updates a finding instead of appending a copy
- adds the structured `scan_history` columns (`target`, `endpoints`, `findings`,
  `duration`, `status`)

A row that cannot be parsed is kept under a `legacy-<id>` fingerprint rather than
discarded.

**Back up first if the data matters** — the duplicate collapse is not reversible:

```bash
cp ~/.local/share/spyder/db/spyder.sqlite ~/spyder-backup.sqlite
```

### Behaviour changes worth knowing

These are fixes, but they change what you see. If you scripted around the old
behaviour, read these.

| Change | Before | Now |
|---|---|---|
| `workspace use <typo>` | silently created an empty workspace | errors, suggests `workspace new` |
| `spyder -w acme scan …` | wrote to `default` — the flag was dropped | writes to `acme` |
| `spyder --profile <bad> workspaces` | exited 0, ignored the profile | exits 1, `profile not found` |
| `--profile` with a bad path | raw `OSError` traceback | clean `profile not found` message |
| Default User-Agent | `SPYDER/0.1` forever | `SPYDER/1.0.0`, tracks the release |

**If a script relied on `workspace use` creating workspaces**, change it to
`workspace new`, which is explicit and always worked.

**If a script parsed the User-Agent**, it now carries the real version.

**If a script passed `-w` before the subcommand** and silently got `default`,
it now gets the workspace you asked for. Check which workspace your data has
actually been landing in:

```bash
spyder workspaces
```

### New in 1.0.0

- `spyder findings [-w WS]` — list findings from the CLI without exporting a
  report first.
- `spyder plugins` now prints every plugin directory it scanned.
- `report`, `findings`, and `workspaces` accept the full global flag set
  (`-w`, `--profile`, `--proxy`, `--debug`, `--no-anim`), like the other
  subcommands always did.
- Startup for `--help` / `--version` dropped from ~700 ms to ~66 ms. No API
  change; if you import from `spyder.__main__`, note that heavy subsystems are
  no longer imported as a side effect — import them from their own modules
  (`spyder.core.orchestrator`, `spyder.reporting.engine`, …) or via the
  `spyder.cli` facade.

### Plugins

The plugin API is unchanged; existing plugins keep working.

One clarification: the repository's own `plugins/` directory was **never**
auto-loaded, though the old README implied it was. If you dropped a plugin there
and wondered why it never ran, that is why. Put it in
`~/.local/share/spyder/plugins/` (or configure `plugin_dirs`) and confirm with:

```bash
spyder plugins
```

See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md).

### Rolling back

```bash
git checkout v0.1.0 && pip install -e .
```

A 1.0.0 database opened by 0.1.0 still works — the added columns and index are
additive, and 0.1.0 ignores them. Findings collapsed by the deduplication
migration do not come back; restore your backup if you need them.

---

## Versioning policy from 1.0.0 onward

SPYDER follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- **PATCH** (1.0.x) — bug fixes, no behaviour change you would script against
- **MINOR** (1.x.0) — new commands, flags, connectors, and plugin contracts;
  always backward compatible
- **MAJOR** (x.0.0) — breaking changes to the CLI surface, the plugin API, or the
  database schema

What is covered by that promise:

- CLI subcommands, flags, and exit codes
- REPL command names and aliases
- The plugin base classes and their method signatures
- `Finding`, `Endpoint`, `Target`, and `Parameter` field names
- Report JSON structure
- Configuration keys and `SPYDER_*` environment variables

What is not:

- Anything prefixed with `_`
- Terminal layout, colours, and table formatting
- Log formats
- Internal module paths — import from `spyder.cli` or the documented modules

Breaking changes get a deprecation warning in one MINOR release before removal
in the next MAJOR, and every one is listed here.
