# Contributing to SPYDER

Thanks for wanting to help. SPYDER is used by security professionals on real
engagements, so the bar is correctness and trustworthiness over feature count.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Scope posture — read this first

This is the fastest way to know whether your PR will be accepted.

**Welcome:**

- Discovery, crawling, and endpoint-inventory improvements
- Analysis, fingerprinting, and confidence-scoring improvements
- New connectors for existing recon/scanning tools
- Reporting, UX, documentation, and test improvements
- Performance work backed by a measurement
- Bug fixes with a regression test

**Rejected, regardless of quality:**

- Exploitation payloads or automated attack sequences
- Scope-bypass or WAF-evasion logic
- Anything that fabricates, estimates, or infers findings that were not observed
- Credential harvesting or storage of unredacted secrets
- Features that make unauthorized use easier or attribution harder

SPYDER maps and analyses attack surface. It does not exploit. That line is what
makes it defensible to run inside a client's network, and it is not negotiable.

## Development setup

```bash
git clone https://github.com/joshwa-n/spyder.git
cd spyder
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest                 # 415 tests, ~13 min
pytest -m "not pty"    # 388 of them, ~1 min — skips the terminal tests
```

The 27 `pty`-marked cases drive the real CLI on a pseudo-terminal, so they cost
seconds each rather than milliseconds. They are part of the default run because
the defects they cover (a Ctrl+C that killed the whole console, a terminal left
in the alternate screen after SIGTERM) are invisible to every in-process test.
Use `-m "not pty"` for a fast inner loop; run the full suite before you push.

Use a throwaway data directory so you never touch real engagement data:

```bash
export SPYDER_HOME=/tmp/spyder-dev
```

## Before you open a PR

All three must pass — CI runs exactly these:

```bash
ruff check .           # lint (line length 100; E,F,W,I,UP,B)
mypy spyder/           # type check — must stay clean
pytest                 # full suite
```

`ruff format .` to format.

## Code conventions

- Python 3.12+, `from __future__ import annotations` at the top of every module
- Type-annotate public functions; `mypy spyder/` must stay clean
- Match the surrounding style — comment density, naming, and idiom
- Comments explain **why**, not what. Non-obvious decisions deserve a sentence;
  restating the code does not
- Keep `spyder/__main__.py` free of module-level heavy imports (see
  [ARCHITECTURE.md](docs/ARCHITECTURE.md#startup-cost)) — it is a measured 10×
  startup regression
- One owner per concern: terminal control lives only in `spyder/ui/terminal.py`,
  banner content only in `spyder/ui/banner.py`. Don't add a second path
- **No stubs.** Don't merge a function that exists only to satisfy an interface.
  A missing feature is better than one that silently does nothing

## Testing

Every bug fix needs a regression test that fails before the fix and passes
after. State that you verified this in the PR.

- Tests live in `tests/`, named `test_*.py`
- Async tests work automatically (`asyncio_mode = "auto"`)
- Use `respx` to mock HTTP — **tests must never touch the network**
- Use `tmp_path` for filesystem work — tests must never write to a real
  `SPYDER_HOME`
- Test behaviour a user could observe, not private implementation details

## Commit messages

```
<area>: <what changed, imperative>

Why this change is needed, and anything non-obvious about the approach.
Note what you verified: "Full suite passed. ruff and mypy clean."
```

Example: `connectors: reject empty target before spawning the binary`

## Pull requests

- One logical change per PR
- Fill in the PR template — especially what you verified and how
- Say plainly what you did *not* test. An honest limitation is worth more than
  an untested claim; "verified" in this project means you ran it

## Reporting bugs

Open an issue with the bug template. Include `spyder --version`, your OS and
Python version, exact reproduction steps, and what you expected instead.

**Redact everything from unauthorized or client systems** — hostnames, IPs,
findings, credentials. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting vulnerabilities

Privately, never in an issue. See [SECURITY.md](SECURITY.md).

## Writing plugins

You do not need to modify SPYDER to extend it — see
[docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md). Plugins can live in
your own repository.

## Project layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the package map, dependency
rules, and the command/connector lifecycles.
