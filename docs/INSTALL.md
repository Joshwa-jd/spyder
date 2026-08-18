# Installing SPYDER

## Requirements

| | |
|---|---|
| Python | 3.12 or newer |
| OS | Linux (developed and tested on Kali; any modern Linux works) |
| Disk | ~200 MB including dependencies |

macOS should work but is not covered by CI. Windows is not supported — the
connectors assume POSIX tooling.

## Install from a clone

```bash
git clone https://github.com/joshwa-n/spyder.git
cd spyder
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

`-e` (editable) keeps the install pointed at your working copy, which is what you
want for development. For a plain install, drop the `-e`.

Verify:

```bash
spyder --version        # SPYDER 1.0.0
spyder --help
```

## Optional extras

```bash
pip install -e ".[pdf]"    # PDF report export (weasyprint)
pip install -e ".[fast]"   # uvloop + orjson speedups
pip install -e ".[dev]"    # pytest, ruff, mypy, respx
pip install -e ".[pdf,fast,dev]"
```

Everything except PDF export works without extras. Requesting `report pdf`
without `weasyprint` prints a clear message telling you to install it — it does
not crash.

### weasyprint system libraries

`weasyprint` needs native libraries. On Debian/Kali:

```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi-dev
```

## External tools (for connectors)

SPYDER orchestrates tools you install yourself; it never bundles or downloads
them. Each connector is optional — SPYDER runs fine with none of them installed,
and a missing binary produces a clear error rather than a fabricated result.

| Connector | Binary | Install |
|---|---|---|
| subfinder | `subfinder` | `apt install subfinder` or ProjectDiscovery release |
| amass | `amass` | `apt install amass` |
| assetfinder | `assetfinder` | `go install github.com/tomnomnom/assetfinder@latest` |
| httpx | `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | `waybackurls` | `go install github.com/tomnomnom/waybackurls@latest` |
| ffuf | `ffuf` | `apt install ffuf` |
| nuclei | `nuclei` | `apt install nuclei` |
| sqlmap | `sqlmap` | `apt install sqlmap` |
| Burp | — | REST API; no binary needed |

Check what SPYDER can see:

```bash
spyder plugins
```

## Where SPYDER keeps data

SPYDER follows XDG conventions, so it behaves identically from any working
directory after install:

```
~/.local/share/spyder/
├── db/spyder.sqlite     workspaces, endpoints, findings, history
├── workspaces/<name>/   evidence, screenshots, notes.md, timeline.jsonl
├── reports/             exported reports
├── logs/                spyder.log
├── configs/             your saved profiles
└── plugins/             drop-in plugins (auto-loaded at startup)
```

Override the whole tree with `SPYDER_HOME`:

```bash
SPYDER_HOME=/engagements/acme spyder -w acme
```

This is the clean way to keep engagements separated on disk, and the easiest way
to try SPYDER without touching your home directory.

## Upgrading

```bash
cd spyder && git pull && pip install -e .
```

Workspace databases migrate themselves in place on first open. See
[MIGRATION.md](MIGRATION.md).

## Uninstalling

```bash
pip uninstall spyder-recon
rm -rf ~/.local/share/spyder    # deletes all engagement data — be sure
```

## Troubleshooting

**`spyder: command not found`** — the venv is not active, or `~/.local/bin` is
not on `PATH`. Use `python3 -m spyder` to confirm the package itself is fine.

**`ModuleNotFoundError: spyder`** — you are outside the venv you installed into.

**`PDF export requires 'weasyprint'`** — install the `pdf` extra and its system
libraries (above).

**`'<tool>' not found on PATH`** — that connector's binary is not installed or
not on `PATH`. `spyder plugins` lists what is available. Go-installed tools land
in `~/go/bin`, which is often missing from `PATH`.

**A plugin isn't loading** — run `spyder plugins`; it prints every directory it
scanned. Plugins must live in one of those. See
[PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md).
