"""Built-in commands for the SPYDER console."""
from __future__ import annotations

import time

from rich.markup import escape

from ..core.models import parse_target
from ..reporting.engine import ReportEngine
from . import theme
from .commands import Command, CommandRegistry
from .display import findings_table, history_table, stats_panel, workspaces_table
from .theme import DIM_GREY, NEON_RED, OFF_WHITE

# Category key → display title, in the order help renders them.
_HELP_CATEGORIES: list[tuple[str, str]] = [
    ("recon", "Recon"),
    ("analysis", "Analysis"),
    ("workspace", "Workspace"),
    ("reporting", "Reporting"),
    ("core", "Core"),
]


def _render_command_help(ctx, cmd) -> None:
    """Render a full, framework-quality help page for one command.

    Sections mirror man-page / msfconsole conventions: description, usage,
    arguments, examples, related commands, exit codes. Empty sections are
    omitted so sparse (e.g. plugin) commands stay tidy.
    """
    lines: list[str] = []
    desc = cmd.description or cmd.summary
    lines.append(f"[bold {OFF_WHITE}]{escape(cmd.name)}[/] — {escape(desc)}")
    lines.append("")
    lines.append(f"[{DIM_GREY}]Usage:[/] {escape(cmd.usage or cmd.name)}")
    if cmd.aliases:
        lines.append(f"[{DIM_GREY}]Aliases:[/] {escape(', '.join(cmd.aliases))}")
    if cmd.arguments:
        lines.append("")
        lines.append(f"[{DIM_GREY}]Arguments:[/]")
        width = max(len(a) for a, _ in cmd.arguments)
        for a, meaning in cmd.arguments:
            lines.append(f"  [bold {OFF_WHITE}]{escape(a.ljust(width))}[/]  {escape(meaning)}")
    if cmd.examples:
        lines.append("")
        lines.append(f"[{DIM_GREY}]Examples:[/]")
        for ex in cmd.examples:
            lines.append(f"  [{NEON_RED}]spyder>[/] {escape(ex)}")
    if cmd.exit_codes:
        lines.append("")
        lines.append(f"[{DIM_GREY}]Exit codes:[/]")
        for code, meaning in cmd.exit_codes:
            lines.append(f"  [bold {OFF_WHITE}]{escape(str(code))}[/]  {escape(meaning)}")
    if cmd.related:
        lines.append("")
        lines.append(f"[{DIM_GREY}]Related:[/] {escape(', '.join(cmd.related))}")
    ctx.console.print(theme.secondary_panel("\n".join(lines), title=f"help · {cmd.name}"))


async def _cmd_help(ctx, args):
    if args:
        cmd = ctx.registry.resolve(args[0])
        if not cmd:
            ctx.console.print(theme.err(f"no such command: {escape(args[0])}"))
            suggestions = ctx.registry.suggest(args[0])
            if suggestions:
                ctx.console.print(f"[{DIM_GREY}]did you mean:[/] {', '.join(suggestions)}")
            return
        _render_command_help(ctx, cmd)
        return

    # Full help: one adaptive section per category, no fixed/truncating widths.
    by_cat: dict[str, list[Command]] = {}
    for cmd in ctx.registry.all():
        by_cat.setdefault(cmd.category, []).append(cmd)
    known = {key for key, _ in _HELP_CATEGORIES}
    ordering = _HELP_CATEGORIES + [
        (k, k.replace("_", " ").title()) for k in sorted(by_cat) if k not in known
    ]
    for key, title in ordering:
        group = by_cat.get(key)
        if not group:
            continue
        table = theme.base_table(title)
        table.add_column("Command", style=f"bold {OFF_WHITE}", no_wrap=True)
        table.add_column("Aliases", style=DIM_GREY, no_wrap=True)
        table.add_column("Description", overflow="fold")
        for cmd in sorted(group, key=lambda c: c.name):
            table.add_row(cmd.name, ", ".join(cmd.aliases) or "—", cmd.summary)
        ctx.console.print(table)
    ctx.console.print(
        f"[{DIM_GREY}]run[/] [bold {NEON_RED}]help <command>[/] "
        f"[{DIM_GREY}]for usage · all testing must be authorized[/]"
    )


async def _cmd_workspace(ctx, args):
    if not args:
        ctx.console.print(f"current workspace: [bold {NEON_RED}]{ctx.workspace}[/]")
        return
    sub = args[0]
    if sub == "list":
        ctx.console.print(workspaces_table(ctx.orch.wm.list_workspaces()))
    elif sub == "use" and len(args) > 1:
        from .banner import render_banner
        name = args[1]
        # `use` switches to an EXISTING workspace (its documented contract). Guard
        # against silently creating one on a typo — otherwise `workspace use acme2`
        # (meant to be `acme`) would drop the operator into a new empty workspace
        # and look as though their findings vanished. Creation is `workspace new`.
        if ctx.orch.wm.get_id(name) is None:
            ctx.console.print(theme.err(f"no such workspace: {escape(name)}"))
            ctx.console.print(
                f"[{DIM_GREY}]create it with[/] [bold {NEON_RED}]workspace new {escape(name)}[/] "
                f"[{DIM_GREY}]· see all with[/] [bold {NEON_RED}]workspace list[/]"
            )
            return
        ctx.switch_workspace(name)
        # Fresh screen + the one canonical banner, then the confirmation line —
        # identical banner to startup / clear / dashboard exit.
        render_banner(ctx.console)
        ctx.console.print(theme.ok(f"switched to workspace [bold {NEON_RED}]{escape(name)}[/]"))
    elif sub == "new" and len(args) > 1:
        from .banner import render_banner
        ctx.orch.wm.create(args[1])
        ctx.switch_workspace(args[1])
        render_banner(ctx.console)
        ctx.console.print(theme.ok(f"created workspace [bold {NEON_RED}]{escape(args[1])}[/]"))
    else:
        ctx.console.print(theme.err("usage: workspace [list | use <name> | new <name>]"))


async def _cmd_scan(ctx, args):
    if not args:
        ctx.console.print(theme.err("usage: scan <url> [--passive]"))
        return
    url = args[0]
    if "--passive" in args:
        ctx.orch.config.passive_mode = True
    try:
        target = parse_target(url)
    except ValueError as exc:
        ctx.console.print(theme.err(escape(str(exc))))
        return
    ctx.last_target = str(target.base_url)
    start = time.monotonic()
    with ctx.console.status(f"[bold {NEON_RED}]recon in progress…[/]", spinner="dots"):
        endpoints = await ctx.orch.recon(target)
        findings = await ctx.orch.run_analyzers(endpoints)
    elapsed = time.monotonic() - start
    req_count = len(ctx.orch.last_transactions)
    ctx.console.print(stats_panel(req_count, len(endpoints), len(ctx.orch.findings()), elapsed))
    ctx.console.print(findings_table(findings or ctx.orch.findings()))
    ctx.console.print(theme.ok(
        f"scan completed — {len(endpoints)} endpoints, {len(ctx.orch.findings())} findings in {elapsed:.1f}s"
    ))


async def _cmd_crawl(ctx, args):
    if not args:
        ctx.console.print(theme.err("usage: crawl <url>"))
        return
    try:
        target = parse_target(args[0])
    except ValueError as exc:
        ctx.console.print(theme.err(escape(str(exc))))
        return
    ctx.last_target = str(target.base_url)
    with ctx.console.status(f"[bold {NEON_RED}]crawling…[/]", spinner="dots"):
        endpoints = await ctx.orch.recon(target)
    for ep in endpoints[:100]:
        params = ",".join(p.name for p in ep.params) or "—"
        ctx.console.print(
            f"  [{OFF_WHITE}]{ep.method.value}[/] {ep.url}  [{DIM_GREY}]params:[/] {params}"
        )
    ctx.console.print(theme.ok(f"crawl completed — {len(endpoints)} endpoints discovered"))


async def _cmd_connector(ctx, args):
    if len(args) < 2:
        avail = ", ".join(ctx.orch.registry.connectors)
        ctx.console.print(theme.err("usage: connector <name> <url> [key=val ...]"))
        ctx.console.print(f"[{DIM_GREY}]available:[/] {avail}")
        return
    name, url = args[0], args[1]
    options = {}
    for kv in args[2:]:
        k, _, v = kv.partition("=")
        options[k] = True if v == "" else v
    try:
        with ctx.console.status(f"[bold {NEON_RED}]running {name}…[/]", spinner="dots"):
            findings = await ctx.orch.run_connector(name, url, options)
        ctx.console.print(findings_table(findings))
        ctx.console.print(theme.ok(f"{escape(name)} completed — {len(findings)} finding(s)"))
    except Exception as exc:
        ctx.console.print(theme.err(f"connector error: {escape(str(exc))}"))


async def _cmd_findings(ctx, args):
    ctx.console.print(findings_table(ctx.orch.findings()))


async def _cmd_report(ctx, args):
    fmt = args[0] if args else "html"
    try:
        engine = ReportEngine()
        path = engine.export(
            fmt, ctx.workspace, ctx.last_target or "—", ctx.orch.findings(), ctx.orch.config.reports_dir
        )
    except ValueError as exc:
        # Unknown format — a user-input error, not a crash.
        ctx.console.print(theme.err(str(exc)))
        ctx.console.print(f"[{DIM_GREY}]valid formats:[/] html, json, md, pdf")
        return
    except RuntimeError as exc:
        # e.g. PDF requested without the optional weasyprint dependency.
        ctx.console.print(theme.warn(str(exc)))
        return
    ctx.console.print(theme.ok(f"report written: {path}"))


async def _cmd_replay(ctx, args):
    txns = ctx.orch.last_transactions
    if not txns:
        ctx.console.print(theme.warn("no recorded transactions yet — run a scan first"))
        return
    if args and args[0].isdigit():
        idx = int(args[0])
        if idx >= len(txns):
            ctx.console.print(theme.err(f"index out of range (0–{len(txns)-1})"))
            return
        original = txns[idx]
        from ..http.client import HTTPClient
        with ctx.console.status(f"[bold {NEON_RED}]replaying #{idx}…[/]", spinner="dots"):
            async with HTTPClient(ctx.orch.config.http, record=False) as client:
                replayed = await client.replay(original)
        from ..analysis.diff import diff
        d = diff(original, replayed)
        ctx.console.print(
            theme.replay_panel(
                f"[{OFF_WHITE}]{replayed.method}[/] {replayed.url}\n"
                f"status: {original.status} → [bold]{replayed.status}[/]\n"
                f"similarity: [bold]{d.similarity}[/]   length Δ: {d.length_delta:+d}   "
                f"timing Δ: {d.timing_delta_ms:+.0f}ms\n"
                f"notable: {', '.join(d.notable) or 'none'}",
                idx=idx,
            )
        )
        return
    table = theme.base_table("SPYDER · Replay Buffer")
    table.add_column("#", width=4)
    table.add_column("Method", width=7)
    table.add_column("Status", width=7)
    table.add_column("ms", width=8)
    table.add_column("URL", overflow="fold")
    for i, t in enumerate(txns[:50]):
        table.add_row(str(i), t.method, str(t.status or "—"), f"{t.elapsed_ms:.0f}", t.url)
    ctx.console.print(table)
    ctx.console.print(f"[{DIM_GREY}]replay <#> to re-issue a request[/]")



async def _cmd_plugins(ctx, args):
    summary = ctx.orch.registry.summary()
    table = theme.base_table("SPYDER · Plugins & Connectors")
    table.add_column("Category", style=f"bold {OFF_WHITE}", no_wrap=True)
    table.add_column("Count", justify="right", width=5, no_wrap=True)
    table.add_column("Loaded", overflow="fold")
    for kind, names in summary.items():
        loaded = ", ".join(names) if names else f"[{DIM_GREY}]—[/]"
        table.add_row(kind.replace("_", " "), str(len(names)), loaded)
    ctx.console.print(table)
    # Name the directories that were scanned. A plugin dropped somewhere SPYDER
    # does not look simply never appears above; without this line there is
    # nothing on screen to explain why, or where it should have gone.
    dirs = ctx.orch.config.plugin_dirs
    for d in dirs:
        suffix = "" if d.is_dir() else f" [{DIM_GREY}](missing)[/]"
        ctx.console.print(f"[{DIM_GREY}]plugin dir:[/] [{OFF_WHITE}]{escape(str(d))}[/]{suffix}")
    if not dirs:
        ctx.console.print(f"[{DIM_GREY}]no plugin directories configured[/]")


async def _cmd_history(ctx, args):
    rows = ctx.orch.wm.history(ctx.orch.ws_id)
    if not rows:
        ctx.console.print(f"[{DIM_GREY}]no scan history for this workspace[/]")
        return
    ctx.console.print(history_table(rows, ctx.workspace))


async def _cmd_set(ctx, args):
    if len(args) < 2:
        ctx.console.print(theme.err("usage: set <proxy|passive|rate> <value>"))
        return
    key, val = args[0], args[1]
    if key == "proxy":
        ctx.orch.config.http.proxy = None if val in ("off", "none") else val
        ctx.console.print(theme.ok(f"proxy set: {ctx.orch.config.http.proxy}"))
    elif key == "passive":
        ctx.orch.config.passive_mode = val.lower() in ("on", "true", "1", "yes")
        ctx.console.print(theme.ok(f"passive mode: {ctx.orch.config.passive_mode}"))
    elif key == "rate":
        try:
            rate = float(val)
        except ValueError:
            ctx.console.print(theme.err(f"rate must be a number: {escape(val)}"))
            return
        ctx.orch.config.rate_limit.requests_per_second = rate
        ctx.console.print(theme.ok(f"rate limit: {rate}/s"))
    else:
        ctx.console.print(theme.err(f"unknown setting: {escape(key)}"))
        ctx.console.print(f"[{DIM_GREY}]valid settings:[/] proxy, passive, rate")


async def _cmd_dashboard(ctx, args):
    """Launch the persistent Textual SOC dashboard for the current workspace."""
    from .banner import render_banner
    from .dashboard import run_dashboard_async
    from .terminal import terminal_guard

    ctx.console.print(theme.info("launching SPYDER dashboard… ") + f"[{DIM_GREY}](ctrl+c to return)[/]")
    error: str | None = None
    try:
        with terminal_guard():
            await run_dashboard_async(
                ctx.config, workspace=ctx.workspace, profile=ctx.config.profile_name
            )
    except KeyboardInterrupt:
        # User pressed Ctrl+C to leave the dashboard — expected, not an error.
        pass
    except Exception as exc:
        error = str(exc)
    finally:
        # Restore the terminal and repaint the fresh-screen banner through the one
        # owner — identical to startup and `clear`, so cursor/screen state is the
        # same however the dashboard was left (clean exit or Ctrl+C mid-teardown).
        render_banner(ctx.console)
    if error:
        ctx.console.print(theme.err(f"dashboard error: {escape(error)}"))
    ctx.console.print(theme.ok("returned to console") + f" [{DIM_GREY}](workspace {escape(ctx.workspace)})[/]")


async def _cmd_clear(ctx, args):
    """Wipe the screen and repaint the SPYDER banner at row 1, col 1 through the
    single banner owner — identical to startup and dashboard exit."""
    from .banner import render_banner
    render_banner(ctx.console)


async def _cmd_restart(ctx, args):
    """Restart the session in place: re-open the orchestrator on the current
    workspace, drop transient session state, and repaint the one canonical
    banner — the same fresh-screen banner as startup / clear / dashboard exit."""
    from .banner import render_banner
    ctx.switch_workspace(ctx.workspace)  # close + re-open orchestrator, same ws
    ctx.last_target = None
    render_banner(ctx.console)
    ctx.console.print(theme.ok("session restarted") + f" [{DIM_GREY}](workspace {escape(ctx.workspace)})[/]")


async def _cmd_exit(ctx, args):
    ctx.console.print(theme.info("closing console…"))


def register_builtins(registry: CommandRegistry) -> None:
    # Process exit codes shared by commands that are also runnable one-shot as
    # `spyder <command> …` (see spyder.__main__.main). In the REPL these commands
    # never crash the session; the codes apply to CLI/scripted use.
    _cli_exit_codes = (
        ("0", "success"),
        ("1", "error (invalid input, tool failure, or unexpected exception)"),
        ("130", "interrupted (Ctrl+C)"),
    )
    cmds = [
        Command(
            "help", "Show commands or detail for one", _cmd_help, "help [command]", ("?",), "core",
            description="List every command grouped by category, or show a full help page for one command.",
            arguments=(("command", "optional command name to show detailed help for"),),
            examples=("help", "help scan", "help connector"),
            related=("scan", "connector", "report"),
        ),
        Command(
            "scan", "Recon + analyzers against a URL", _cmd_scan, "scan <url> [--passive]", (), "recon",
            description="Crawl a target, discover endpoints, then run passive analyzers over the responses and record findings in the current workspace.",
            arguments=(("url", "target URL, e.g. https://example.com"),
                       ("--passive", "no active probing — observe responses only")),
            examples=("scan https://example.com", "scan https://example.com --passive"),
            related=("crawl", "findings", "report"),
            exit_codes=_cli_exit_codes,
        ),
        Command(
            "crawl", "Crawl & discover endpoints only", _cmd_crawl, "crawl <url>", (), "recon",
            description="Discover endpoints and parameters for a target without running analyzers. Useful for mapping attack surface quickly.",
            arguments=(("url", "target URL to crawl"),),
            examples=("crawl https://example.com",),
            related=("scan", "connector"),
            exit_codes=_cli_exit_codes,
        ),
        Command(
            "connector", "Run an external-tool connector", _cmd_connector, "connector <name> <url> [key=val ...]", ("conn",), "recon",
            description="Run an installed external tool (subfinder, httpx, katana, nuclei, sqlmap, …) against a target and normalize its output into findings. Missing tools produce a clear error — results are never fabricated.",
            arguments=(("name", "connector name (see 'connector' with no args for the list)"),
                       ("url", "target URL or domain"),
                       ("key=val", "connector-specific options, e.g. wordlist=/path, title=1")),
            examples=("connector subfinder https://example.com",
                      "connector nuclei https://example.com",
                      "connector ffuf https://example.com wordlist=/usr/share/wordlists/dirb/common.txt"),
            related=("scan", "plugins", "findings"),
            exit_codes=_cli_exit_codes,
        ),
        Command(
            "findings", "List findings in this workspace", _cmd_findings, "findings", ("f",), "analysis",
            description="Show all findings recorded in the current workspace, ranked by severity.",
            examples=("findings",),
            related=("scan", "report", "replay"),
        ),
        Command(
            "replay", "Show/replay recorded requests", _cmd_replay, "replay [#]", (), "analysis",
            description="List the recorded request/response transactions from the last scan, or re-issue and diff one by index.",
            arguments=(("#", "optional transaction index to replay"),),
            examples=("replay", "replay 3"),
            related=("scan", "findings"),
        ),
        Command(
            "report", "Export a report", _cmd_report, "report [html|json|md|pdf]", ("rpt",), "reporting",
            description="Export the current workspace's findings to a report file. HTML/JSON/Markdown are always available; PDF requires the optional 'weasyprint' dependency.",
            arguments=(("format", "one of html (default), json, md, pdf"),),
            examples=("report", "report json", "report md"),
            related=("findings", "workspace"),
            exit_codes=_cli_exit_codes,
        ),
        Command(
            "workspace", "Manage workspaces", _cmd_workspace, "workspace [list | use <name> | new <name>]", ("ws",), "workspace",
            description="List workspaces, switch to another, or create a new one. Switching repaints the banner and re-scopes findings, history, and reports.",
            arguments=(("list", "list all workspaces"),
                       ("use <name>", "switch to an existing workspace"),
                       ("new <name>", "create and switch to a new workspace")),
            examples=("workspace list", "workspace new acme", "workspace use acme"),
            related=("history", "findings", "restart"),
        ),
        Command(
            "history", "Scan history for this workspace", _cmd_history, "history", (), "workspace",
            description="Show the recorded scan/connector history for the current workspace.",
            examples=("history",),
            related=("workspace", "findings"),
        ),
        Command(
            "dashboard", "Launch the persistent SOC dashboard", _cmd_dashboard, "dashboard", ("dash", "ui"), "core",
            description="Open the full-screen Textual SOC dashboard for the current workspace. Press Ctrl+C to return to the console; the banner repaints on exit.",
            examples=("dashboard",),
            related=("scan", "findings"),
        ),
        Command(
            "plugins", "List loaded plugins & connectors", _cmd_plugins, "plugins", (), "core",
            description="Show every loaded plugin and connector, grouped by category, with which are available.",
            examples=("plugins",),
            related=("connector",),
        ),
        Command(
            "set", "Change a runtime setting", _cmd_set, "set <proxy|passive|rate> <value>", (), "core",
            description="Change a runtime setting for the current session without restarting.",
            arguments=(("proxy <url|off>", "route traffic through a proxy (e.g. Burp), or 'off'"),
                       ("passive <on|off>", "toggle passive mode (no active probing)"),
                       ("rate <n>", "set the request rate limit in requests/second")),
            examples=("set proxy http://127.0.0.1:8080", "set passive on", "set rate 20"),
            related=("scan", "connector"),
        ),
        Command(
            "clear", "Clear the screen", _cmd_clear, "clear", ("cls",), "core",
            description="Wipe the screen and repaint the SPYDER banner at the top — identical to startup.",
            examples=("clear",),
            related=("restart",),
        ),
        Command(
            "restart", "Restart the session (repaint banner)", _cmd_restart, "restart", (), "core",
            description="Restart the session in place: re-open the workspace, drop transient state, and repaint the banner.",
            examples=("restart",),
            related=("clear", "workspace"),
        ),
        Command(
            "exit", "Exit the console", _cmd_exit, "exit", ("quit",), "core",
            description="Close the SPYDER console and return to the shell. Ctrl+D does the same.",
            examples=("exit",),
            related=(),
        ),
    ]
    for c in cmds:
        registry.register(c)
