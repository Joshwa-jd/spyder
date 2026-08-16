# Changelog

All notable changes to SPYDER are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Fingerprint engine reports technology entities, not header roles.** A
  response carrying `Server: nginx/1.24.0` now yields the technology *Nginx*
  (version 1.24.0) with the evidence, evidence source, and confidence that
  support it, rather than the opaque pair `server -> nginx/1.24.0`. Detection is
  structural: a technology is claimed from a header value, a cookie *name*, a
  `<meta name="generator">` value, a markup attribute, or a referenced asset URL
  — never from prose, so a page that merely discusses WordPress is not reported
  as running it.
- **No single passive signal reaches CONFIRMED.** Every passive signal is
  attacker-controlled, so passive evidence tops out at HIGH; promotion to
  CONFIRMED requires agreement from at least two *independent* evidence sources.
  Corroboration is counted per source, so a repeated header is still one
  spoofable opinion.
- Responses with no structural evidence produce no entities — Unknown is
  reported rather than guessed.

### Added

- **Fingerprint ground truth and comparison harness** —
  `verification/comparison/fingerprint_compare.py` scores SPYDER and reference
  tools against a 22-page hand-verified manifest (18 technology claims, 6 pages
  whose correct answer is *nothing*), so precision is measurable and not just
  recall. Measured on that manifest: SPYDER 100.0% precision / 100.0% recall
  (18 TP, 0 FP, 0 FN, 6/6 Unknown pages correct, 7/7 versions);
  WhatWeb 91.7% / 61.1%; httpx 60.0% / 33.3%.
- 42 fingerprint regression tests, including a 100-iteration determinism check.
- **Secret detectors for credentials that were previously missed** — AWS secret
  access key (anchored to an assignment, since a bare 40-character run is not
  evidence), Slack incoming-webhook URLs, Slack `xapp-`/`xoxe-` tokens, GitHub
  fine-grained PATs (`github_pat_…`), and Twilio API Key SIDs. The Twilio
  *Account* SID is deliberately not claimed: it is published in dashboards and
  URLs, so reporting it as a secret would be a false positive.
- **Unquoted `KEY=value` assignments are scanned.** The generic detector
  required quotes around the value, so `.env` files — a primary leak vector —
  went unread.
- **Secret ground truth and comparison harness** —
  `verification/comparison/secret_compare.py` scores SPYDER and TruffleHog
  against a 25-document corpus (15 credential claims, 10 decoys whose correct
  answer is *nothing*). Every credential in the corpus is fake and
  non-functional. Measured: SPYDER 100.0% precision / 100.0% recall
  (15 TP, 0 FP, 0 FN, 10/10 decoys silent), up from 60.0% recall before these
  detectors were added; TruffleHog v2 75.0% / 20.0%, including a false positive
  on AWS's own documented example key.
- 53 secret-detection regression tests, including a 100-iteration determinism
  check.
- **Findings carry their own audit trail.** `Finding` gained `references`,
  `confidence`, `confidence_score`, and a catalogue `key`, and every renderer
  surfaces them — the Markdown and HTML reports previously dropped confidence
  and references entirely.
- **`spyder.reporting.catalogue`** owns the CWE / OWASP / remediation /
  reference mappings as one reviewable table instead of literals restated at
  each call site. Findings that assert a weakness must be classified;
  observational findings are listed as explicitly unclassified, so a missing
  mapping is a decision on the record rather than an oversight.

### Fixed

- **A placeholder word wearing a counter is no longer scored as random.**
  `password1234` cleared both the entropy and character-class bars, so a
  hardcoded weak value was reported with the same confidence as a real
  credential.
- **`recon()` crashed on every target that fingerprinted.** The fingerprint
  finding was built through a helper that was never imported, so any scan of a
  host revealing a technology died with `NameError`. No test exercised the
  orchestrator end-to-end against a live server, which is why a fully green
  suite did not notice.
- **Version-disclosure findings claimed more confidence than their evidence.**
  Confidence was the maximum over *every* detected technology, so the finding
  inherited the score of an entity that disclosed no version and formed no part
  of the claim — reporting `confirmed (88)` beside an evidence block that
  supported only `high (80)`. It is now scored from the versioned evidence
  alone.
- **The ground-truth server desynced its own keep-alive connections.** Request
  bodies were never drained, so an undrained body was parsed as the next
  request line and the following request came back
  `501 Unsupported method ('q=markerGET')`. Any measurement taken after a body
  probe was reading garbage, and its 501s leaked BaseHTTP's Python banner into
  a site whose technology signals are supposed to be declared. The oracle is
  now covered by its own calibration tests.
- **Reports are written as UTF-8 regardless of the ambient locale.** Text was
  written at `locale.getpreferredencoding()`, so on a non-UTF-8 locale the HTML
  report's bytes contradicted its own `<meta charset="utf-8">`, and the
  Markdown and HTML writers raised `UnicodeEncodeError` — defeated by the em
  dash in their own footers, with no finding content required. Not reachable on
  a supported platform under a natural configuration (PEP 538 coerces C/POSIX
  to UTF-8); fixed as robustness, with all 11 file-IO sites made explicit.

## [1.0.0] — 2026-07-27

First public release. SPYDER is now a stable, documented framework with a
supported API, a release process, and CI.

### Added

- **`spyder findings`** — list a workspace's findings from the CLI. Previously
  only the REPL had it, so scripted use had to export a whole report just to see
  what a workspace held.
- **Plugin-directory transparency** — `spyder plugins` (and the REPL's
  `plugins`) now print every directory that was scanned, so a plugin dropped in
  the wrong place produces a visible explanation instead of silence.
- **PEP 561 `py.typed`** — SPYDER ships its inline type hints, so plugin authors
  and downstream code get them from mypy/pyright without a stub package.
- **Documentation suite** — `docs/INSTALL.md`, `docs/QUICKSTART.md`,
  `docs/PLUGIN_DEVELOPMENT.md`, `docs/MIGRATION.md`, root `CONTRIBUTING.md`,
  `SECURITY.md`, `CODE_OF_CONDUCT.md`, and a rewritten `README.md`. Every
  documented command and code example was executed against the shipped build.
- **CI and release engineering** — GitHub Actions for lint/type-check, tests on
  Python 3.12 and 3.13, packaging verification (all three entry points must
  report identical versions from a clean wheel install), security invariants,
  CodeQL, and Dependabot. A tagged release verifies that the tag, the package
  version, and the CHANGELOG agree before it builds.
- **Issue and PR templates** covering the project's scope posture and the
  requirement to redact unauthorized-target data.
- Uniform connector lifecycle (`initialize/validate/execute/parse/cleanup/status`
  plus `invoke()`) shared by every connector.
- `spyder.cli` package (documented CLI import surface) and `spyder.core.pipeline`
  (named command-lifecycle stages).
- Version-controlled baseline of the framework (initial `git` history).

### Fixed

- **`spyder --profile <path> workspaces` silently ignored the profile.** It
  called `load_config()` with no arguments, so a mistyped or missing profile
  exited 0 and printed a workspace table, while every other subcommand reported
  `profile not found`. All subcommands now resolve configuration through one
  helper, and `report`/`findings`/`workspaces` accept the full global flag set.
- **`workspace use <name>` silently created a non-existent workspace**, so a typo
  dropped the operator into a new empty workspace that looked like lost
  findings. It now errors with a hint; creation stays `workspace new`.
- **Global flags before the subcommand were discarded** — `spyder -w acme scan …`
  wrote to `default`. The subparser's defaults overwrote the pre-subcommand
  value; fixed with `argparse.SUPPRESS` on the duplicates.
- **A missing or malformed `--profile` raised a raw traceback**; it now reports
  `profile not found` / `invalid YAML`.
- **The default User-Agent advertised `SPYDER/0.1` forever.** It is now derived
  from `spyder.__version__`.
- **`pyproject.toml` carried a second hardcoded version** that could drift from
  `spyder.__version__`. The packaged version is now read from the package, and
  CI fails a release whose tag, metadata, and module version disagree.
- **The README claimed the repository's `plugins/` directory was auto-loaded.**
  It never was — only `$SPYDER_HOME/plugins` and configured `plugin_dirs` are
  scanned. The documentation now describes the three real ways to load a plugin,
  each verified.

### Changed

- **Startup is ~10× faster for the most-run commands.** `spyder/__main__.py`
  imported the orchestrator, HTTP stack, reporting engine, and the whole
  Rich/Textual UI at module scope — about 625 ms of the 700 ms that
  `spyder --version` and `spyder --help` took, on paths that touch none of it.
  Subsystems are now imported inside the handler that needs them.
  Measured: **700 ms → 66 ms**. A test pins the import surface so it cannot
  regress.
- `docs/CONTRIBUTING.md` moved to the repository root (GitHub convention) and
  was substantially expanded.
- Development status classifier: Beta → Production/Stable.

### Security

No vulnerabilities were found in this pass. The audit covered command injection,
unsafe subprocess use, path traversal, temporary-file handling, credential
leakage into logs/reports/database, unsafe deserialization, and dynamic
evaluation. The properties below are now enforced by tests
(`tests/test_security_invariants.py`) as well as by review:

- No `shell=True`, `os.system`, `eval`, `exec`, `pickle`, or `yaml.load` anywhere
  in `spyder/`; external tools are spawned with `create_subprocess_exec` and an
  argument list.
- Workspace names and report labels pass through `safe_slug()`, so a label like
  `../../etc/passwd` cannot steer a write outside the data directory.
- HTML reports autoescape — including `.html.j2` templates, which
  `select_autoescape` would otherwise miss — so attacker-influenced finding
  fields cannot become stored XSS in the analyst's browser.
- Detected secrets are redacted at extraction; the unredacted value is scored in
  memory and never reaches the database, reports, or logs.
- TLS verification is on by default.

### Verified

- Full test suite: **335 passing** (`pytest`), `ruff check .` clean,
  `mypy spyder/` clean across 68 source files.
- Report export across JSON / Markdown / HTML / PDF on real, empty, Unicode, and
  2,000-finding datasets; HTML output escapes attacker-influenced fields; PDF
  degrades gracefully when `weasyprint` is absent.
- Performance measured on this machine: startup 66 ms; a 2,000-finding report
  renders in 31 ms (JSON), 62 ms (Markdown), 242 ms (HTML).
- Entry points: `spyder`, `python -m spyder`, and `python main.py` resolve to the
  same CLI/REPL and report identical versions from a clean wheel install.
- Every command, flag, and code example in the documentation was executed
  against the shipped build.

### Known limitations

- Live scanning and crawling against real network targets is exercised by hand,
  not by CI — the test suite never touches the network by design.
- The Textual dashboard and the REPL are covered by mount/unmount and piped-input
  tests, but a human TTY session (Ctrl+C / Ctrl+Q / terminal resize) is verified
  manually.
- PyPI publishing is prepared but disabled in the release workflow until the
  project name is claimed and a Trusted Publisher is configured.

## [0.1.0]

### Added
- Interactive REPL and one-shot CLI (`scan`, `crawl`, `connector`, `report`,
  `workspaces`, `plugins`, `dashboard`) sharing a single entry point.
- Async orchestrator with an event bus for live progress.
- Plugin framework: analyzers, reporters, connectors, recon, replay, and
  dashboard-widget contracts with directory-based discovery.
- External-tool connectors (subprocess, no shell): subfinder, amass,
  assetfinder, httpx, katana, gau, waybackurls, ffuf, nuclei, sqlmap, Burp.
- Workspace engine with SQLite-backed persistence and de-duplicated findings.
- Reporting engine (JSON / Markdown / HTML / PDF) with CWE/OWASP mapping.
- Textual SOC dashboard.

[Unreleased]: https://github.com/joshwa-n/spyder/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/joshwa-n/spyder/releases/tag/v1.0.0
