# SPYDER Quickstart

Ten minutes from install to a report. Everything below runs against a target you
are **authorized** to test.

## 0. Install

```bash
pip install -e .
spyder --version
```

## 1. Create a workspace

A workspace is one engagement: its own endpoints, findings, history, evidence,
and reports. Start the console:

```bash
spyder
```

```
spyder(default)> workspace new acme
[+] created workspace acme
spyder(acme)>
```

The prompt always shows the workspace you are in, so you cannot lose track of
where findings are landing.

## 2. Map the target

```
spyder(acme)> scan https://target.example.com
```

`scan` crawls the target, discovers endpoints and parameters, probes for
reflections with benign markers, fingerprints the technology stack passively,
mines served JavaScript for routes and secret patterns, then runs the loaded
analyzers. It prints a stats panel and a findings table when it finishes.

For a purely observational pass:

```
spyder(acme)> scan https://target.example.com --passive
```

To map attack surface without running analyzers:

```
spyder(acme)> crawl https://target.example.com
```

## 3. Bring in your own tools

```
spyder(acme)> connector subfinder target.example.com
spyder(acme)> connector httpx target.example.com
spyder(acme)> connector nuclei https://target.example.com
```

`connector` with no arguments lists what is installed. A missing binary is
reported plainly — SPYDER never invents results to fill a gap.

sqlmap requires explicit acknowledgement that you are authorized:

```
spyder(acme)> connector sqlmap https://target.example.com/item?id=1 authorized=1
```

## 4. Review what you have

```
spyder(acme)> findings          # everything recorded, worst first
spyder(acme)> replay            # the recorded request/response buffer
spyder(acme)> replay 3          # re-issue #3 and diff it against the original
spyder(acme)> history           # what has been run in this workspace
```

## 5. Watch it live

```
spyder(acme)> dashboard
```

The full-screen SOC dashboard streams events as they happen. `Ctrl+W` opens the
replay workbench for request/response diffing, tagging, and annotation. `Ctrl+C`
or `Ctrl+Q` returns you to the console with the terminal intact.

## 6. Export

```
spyder(acme)> report html
spyder(acme)> report json
spyder(acme)> report md
spyder(acme)> report pdf        # needs the [pdf] extra
```

Reports land in `~/.local/share/spyder/reports/`. HTML reports embed the
intelligence graphs and are safe to open in a browser — attacker-influenced
fields are escaped.

## 7. Come back later

```bash
spyder -w acme
```

```
spyder(acme)> findings
spyder(acme)> history
```

Everything is still there. Workspaces are the unit of resume.

## The same thing, scripted

Every console command has a one-shot form for CI, cron, or a shell loop:

```bash
spyder -w acme scan -u https://target.example.com
spyder -w acme connector nuclei -u https://target.example.com
spyder -w acme findings
spyder -w acme report --format json --target target.example.com
spyder workspaces
```

Exit codes: `0` success, `1` error, `2` bad arguments, `130` interrupted.

```bash
# fail a pipeline when the scan does not complete
spyder -w acme scan -u https://target.example.com || exit 1
```

## Tuning a run

In the console, without restarting:

```
spyder(acme)> set proxy http://127.0.0.1:8080   # route through Burp
spyder(acme)> set passive on                    # stop active probing
spyder(acme)> set rate 5                        # 5 requests/second
```

Persistently, via a YAML profile:

```bash
spyder --profile configs/passive.yaml -w acme
```

## Where to go next

- [INSTALL.md](INSTALL.md) — extras, external tools, data locations
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) — write your own analyzer or connector
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit together
