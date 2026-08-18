# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ (pre-release) |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's [Security Advisories][advisories] on the
repository (Security → Report a vulnerability). If that is unavailable to you,
email the maintainer listed on the GitHub profile.

Please include:

- what the issue is and what an attacker gains
- affected version (`spyder --version`) and OS
- steps to reproduce, ideally a minimal case
- any proof-of-concept you have

**What to expect:** acknowledgement within 72 hours, an assessment with a fix
timeline within 7 days, and credit in the release notes unless you'd rather stay
anonymous. Please give us 90 days before public disclosure, or less if a fix
ships sooner.

[advisories]: https://github.com/joshwa-n/spyder/security/advisories/new

## What is in scope

SPYDER is a security tool, so "it sends requests to a target" is the intended
behaviour, not a vulnerability. In scope:

- **Command injection** via targets, options, workspace names, or plugin input
- **Path traversal** — anything that writes outside the SPYDER data directory
- **Code execution** through report templates, profiles, or plugin loading
- **Credential leakage** — secrets written unredacted to disk, logs, or reports
- **Scope escape** — SPYDER contacting a host the operator did not authorize
- **XSS in generated HTML reports** via attacker-influenced finding fields
- Dependency vulnerabilities that are actually reachable from SPYDER's code

## What is out of scope

- Missing rate limits or "SPYDER can be used to scan a target" — that is the tool
- Vulnerabilities in the external tools SPYDER orchestrates (report those to
  nuclei, sqlmap, subfinder, etc. directly)
- Anything requiring the attacker to already control the machine SPYDER runs on
- Social engineering, physical access, or self-XSS
- Findings from automated scanners with no demonstrated impact

## Design commitments

These are properties the project holds itself to, with test coverage:

- **No shell.** External tools are invoked with `create_subprocess_exec` and an
  argument list. `shell=True` appears nowhere in the codebase.
- **No dynamic evaluation.** No `eval`, `exec`, or `pickle` on untrusted input.
  YAML profiles load through `yaml.safe_load`.
- **Filesystem labels are slugged.** Workspace names and report labels pass
  through `safe_slug()`, which strips path separators, so a name like
  `../../etc/passwd` cannot steer a write outside the data directory.
- **HTML reports autoescape.** Finding titles, endpoints, and tool output are
  attacker-influenced; the Jinja environment escapes `.html.j2` templates so
  report output cannot become stored XSS in the analyst's browser.
- **Secrets are redacted at extraction.** Detected credentials are analysed
  unredacted only in memory; only the redacted form reaches the database,
  reports, or logs.
- **TLS verification is on by default** (`http.verify_tls`).
- **Scope is enforced centrally.** `ScopeGuard` gates outgoing requests.

## Using SPYDER responsibly

SPYDER is for **authorized** security testing. Running it against systems you do
not have explicit written permission to test is illegal in most jurisdictions.
The authors accept no responsibility for misuse.

The project does not accept contributions that add exploitation payloads,
automated attack sequences, or scope/WAF evasion. See
[CONTRIBUTING.md](CONTRIBUTING.md).
