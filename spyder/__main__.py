"""SPYDER — unified CLI + REPL entry point.

All three invocation styles route through here:
    spyder                     → interactive REPL (no subcommand)
    spyder scan -u ...         → one-shot CLI mode
    python3 main.py            → same as above via main.py shim
    python3 -m spyder          → same as above

Behaves like professional Kali tools:
    sqlmap      → no args = help/interactive
    nuclei      → no args = help
    ffuf        → no args = help
    spyder      → no args = interactive REPL   ← our choice, documented clearly

Import policy
-------------
Only ``argparse`` and ``spyder.__version__`` are imported at module level. The
heavy subsystems (orchestrator, HTTP stack, reporting, Rich/Textual UI) are
imported inside the command handlers instead. Building the parser used to drag
in the entire framework — ~625 ms of the ~700 ms that ``spyder --version`` and
``spyder --help`` took — for paths that never touch any of it. Keeping the
module-level surface tiny makes help, version, and argparse errors respond in
tens of milliseconds, the way nuclei/ffuf do, without changing any behaviour.
"""
from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from spyder import __version__

if TYPE_CHECKING:  # heavy imports for type checking only — never at runtime
    from rich.console import Console

    from spyder.core.orchestrator import Orchestrator

# ── Lazy subsystem access ─────────────────────────────────────────────────────

def _install_uvloop() -> None:
    """Install the optional uvloop policy before any asyncio.run() call."""
    try:
        import uvloop  # type: ignore[import-untyped]
    except ImportError:
        return
    uvloop.install()


def _run_async(coro) -> None:
    """Run a coroutine on a fresh event loop, with uvloop if it is installed."""
    import asyncio

    _install_uvloop()
    asyncio.run(coro)


def _console() -> Console:
    """The single Rich console, imported on demand."""
    from spyder.ui.terminal import console

    return console


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_cli_config(args: argparse.Namespace):
    """Load configuration for a one-shot command, honouring the global flags.

    Every subcommand resolves ``--profile``/``--proxy``/``--passive``/``--debug``
    through here so a flag is never silently ignored by one command while being
    honoured by another (a mistyped ``--profile`` must fail the same way for
    ``workspaces`` as it does for ``scan``).
    """
    from spyder.core.config import load_config
    from spyder.utils.logging import setup_logging

    cfg = load_config(getattr(args, "profile", None))
    if getattr(args, "proxy", None):
        cfg.http.proxy = args.proxy
    if getattr(args, "passive", False):
        cfg.passive_mode = True
    setup_logging(log_dir=cfg.logs_dir, debug=getattr(args, "debug", False))
    return cfg


def _make_orchestrator(args: argparse.Namespace) -> Orchestrator:
    from spyder.core.orchestrator import Orchestrator

    cfg = _load_cli_config(args)
    return Orchestrator(cfg, getattr(args, "workspace", "default"))


def _cli_banner(args: argparse.Namespace) -> None:
    """Paint the one-shot banner for CLI (scan/crawl) mode through the single
    banner owner — identical to the REPL, `clear`, and dashboard exit.
    ``--no-anim`` prints the banner in place instead of on a fresh screen."""
    from spyder.ui.banner import render_banner

    render_banner(_console(), clear_first=not getattr(args, "no_anim", False))


# ── Command handlers ──────────────────────────────────────────────────────────

async def _cmd_scan(args: argparse.Namespace) -> None:
    import time

    from rich.markup import escape

    from spyder.core.models import parse_target
    from spyder.ui import theme
    from spyder.ui.display import findings_table, stats_panel
    from spyder.ui.theme import DIM_GREY, OFF_WHITE

    console = _console()
    target = parse_target(args.url, args.scope or [])
    _cli_banner(args)
    orch = _make_orchestrator(args)
    start = time.monotonic()
    try:
        endpoints = await orch.recon(target)
        findings = await orch.run_analyzers(endpoints)
        elapsed = time.monotonic() - start
        console.print(stats_panel(len(orch.last_transactions), len(endpoints), len(orch.findings()), elapsed))
        console.print(findings_table(findings or orch.findings()))
        console.print(theme.ok(
            f"scan completed — {len(endpoints)} endpoints, {len(orch.findings())} findings in {elapsed:.1f}s"
        ))
        console.print(
            f"[{DIM_GREY}]export with[/] [{OFF_WHITE}]spyder report -w {escape(args.workspace)}[/]"
        )
    finally:
        orch.close()


async def _cmd_crawl(args: argparse.Namespace) -> None:
    from spyder.core.models import parse_target
    from spyder.ui import theme
    from spyder.ui.theme import DIM_GREY, OFF_WHITE

    console = _console()
    target = parse_target(args.url, args.scope or [])
    _cli_banner(args)
    orch = _make_orchestrator(args)
    try:
        endpoints = await orch.recon(target)
        for ep in endpoints[:200]:
            params = ",".join(p.name for p in ep.params) or "—"
            console.print(f"  [{OFF_WHITE}]{ep.method.value}[/] {ep.url}  [{DIM_GREY}]params:[/] {params}")
        console.print(theme.ok(f"crawl completed — {len(endpoints)} endpoints discovered"))
    finally:
        orch.close()


async def _cmd_connector(args: argparse.Namespace) -> None:
    from rich.markup import escape

    from spyder.ui import theme
    from spyder.ui.display import findings_table

    console = _console()
    orch = _make_orchestrator(args)
    try:
        options: dict = {}
        for kv in args.opt or []:
            k, _, v = kv.partition("=")
            options[k] = v
        if args.authorized:
            options["authorized"] = True
        findings = await orch.run_connector(args.name, args.url, options)
        console.print(findings_table(findings))
        console.print(theme.ok(f"{escape(args.name)} completed — {len(findings)} finding(s)"))
    finally:
        orch.close()


def _cmd_report(args: argparse.Namespace) -> None:
    from spyder.core.orchestrator import Orchestrator
    from spyder.reporting.engine import ReportEngine
    from spyder.ui import theme

    cfg = _load_cli_config(args)
    orch = Orchestrator(cfg, args.workspace)
    try:
        findings = orch.findings()
        engine = ReportEngine()
        path = engine.export(args.format, args.workspace, args.target or "—", findings, cfg.reports_dir)
        _console().print(theme.ok(f"report written: {path}"))
    finally:
        orch.close()


def _cmd_findings(args: argparse.Namespace) -> None:
    """List the findings recorded in a workspace — the CLI twin of the REPL's
    ``findings`` command, so a workspace can be inspected from a script without
    having to export a report first."""
    from spyder.ui.display import findings_table

    orch = _make_orchestrator(args)
    try:
        _console().print(findings_table(orch.findings()))
    finally:
        orch.close()


def _cmd_workspaces(args: argparse.Namespace) -> None:
    from spyder.core.orchestrator import Orchestrator
    from spyder.ui.display import workspaces_table

    # Load through the shared helper so `--profile` is validated here exactly as
    # it is for every other subcommand. This command used to call load_config()
    # with no arguments, which silently ignored a mistyped or missing --profile
    # and exited 0 while `scan`/`plugins` reported "profile not found".
    cfg = _load_cli_config(args)
    orch = Orchestrator(cfg, "default")
    try:
        _console().print(workspaces_table(orch.wm.list_workspaces()))
    finally:
        orch.close()


def _cmd_plugins(args: argparse.Namespace) -> None:
    from spyder.ui.theme import DIM_GREY, NEON_RED, OFF_WHITE

    console = _console()
    orch = _make_orchestrator(args)
    try:
        summary = orch.registry.summary()
        console.print(f"[bold {NEON_RED}]Loaded plugins & connectors[/]")
        for kind, names in summary.items():
            console.print(f"  [{OFF_WHITE}]{kind}[/]: {', '.join(names) or '—'}")
        # Show which directories were actually scanned. Without this the plugin
        # contract is invisible: a plugin dropped in the wrong directory simply
        # never appears, with nothing on screen to say where SPYDER looked.
        console.print(f"[bold {NEON_RED}]Plugin directories scanned[/]")
        for d in orch.config.plugin_dirs:
            marker = "" if d.is_dir() else f"  [{DIM_GREY}](missing)[/]"
            console.print(f"  [{OFF_WHITE}]{d}[/]{marker}")
    finally:
        orch.close()


def _cmd_dashboard(args: argparse.Namespace) -> None:
    from spyder.ui.dashboard import run_dashboard
    from spyder.ui.terminal import restore, terminal_guard

    cfg = _load_cli_config(args)
    # terminal_guard covers the paths `finally` cannot: SIGTERM/SIGHUP kill the
    # process without unwinding, and a full-screen app killed that way leaves the
    # terminal in the alternate screen with the cursor hidden.
    try:
        with terminal_guard():
            run_dashboard(cfg, workspace=args.workspace, profile=cfg.profile_name)
    finally:
        restore()


async def _run_repl(workspace: str, profile: str | None, animate: bool) -> None:
    """Launch the interactive REPL — the default when spyder runs with no subcommand."""
    from spyder.core.config import load_config
    from spyder.ui.shell import run_console

    config = load_config(profile)
    await run_console(config, workspace=workspace, animate=animate)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spyder",
        description=(
            "SPYDER — red-team workflow orchestration (authorized testing only)\n"
            "Run without arguments to launch the interactive console."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"SPYDER {__version__}")

    # Optional flags accepted even without a subcommand (REPL mode)
    p.add_argument("-w", "--workspace", default="default",
                   help="Workspace name (default: default)")
    p.add_argument("--profile", metavar="PATH",
                   help="Path to a YAML config profile")
    p.add_argument("--no-anim", action="store_true",
                   help="Disable splash animation")

    sub = p.add_subparsers(dest="command")  # NOT required — absence → REPL

    def _common(sp: argparse.ArgumentParser) -> None:
        """Flags shared by all subcommands.

        ``-w``, ``--profile`` and ``--no-anim`` are ALSO defined on the top-level
        parser (for no-subcommand REPL mode) and share a dest with these. Their
        default here is ``SUPPRESS`` so that, when the flag is not passed to the
        subcommand, the subparser does not overwrite a value the user supplied
        *before* the subcommand (e.g. ``spyder -w acme scan …``). Without this,
        ``-w acme`` placed before ``scan`` was silently reset to ``default``.
        """
        sp.add_argument("-w", "--workspace", default=argparse.SUPPRESS,
                        help="Workspace name (default: default)")
        sp.add_argument("--profile", metavar="PATH", default=argparse.SUPPRESS,
                        help="Path to a YAML config profile")
        sp.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp)")
        sp.add_argument("--debug", action="store_true")
        sp.add_argument("--no-anim", action="store_true", default=argparse.SUPPRESS,
                        help="Disable splash animation")

    # scan
    s = sub.add_parser("scan", help="Recon + analyzers in one pass")
    _common(s)
    s.add_argument("-u", "--url", required=True, metavar="URL")
    s.add_argument("--scope", nargs="*", metavar="HOST", help="In-scope hostnames")
    s.add_argument("--passive", action="store_true", help="No active probing")
    s.set_defaults(func=lambda a: _run_async(_cmd_scan(a)))

    # crawl
    c = sub.add_parser("crawl", help="Crawl & discover endpoints only")
    _common(c)
    c.add_argument("-u", "--url", required=True, metavar="URL")
    c.add_argument("--scope", nargs="*", metavar="HOST")
    c.add_argument("--passive", action="store_true")
    c.set_defaults(func=lambda a: _run_async(_cmd_crawl(a)))

    # connector
    cn = sub.add_parser("connector", help="Run an external-tool connector")
    _common(cn)
    cn.add_argument("name", help="Connector name (nuclei, sqlmap, burp, subfinder, …)")
    cn.add_argument("-u", "--url", required=True, metavar="URL")
    cn.add_argument("--opt", nargs="*", metavar="KEY=VAL",
                    help="Connector options as key=value pairs")
    cn.add_argument("--authorized", action="store_true",
                    help="Confirm you are authorized to test this target (required by sqlmap)")
    cn.set_defaults(func=lambda a: _run_async(_cmd_connector(a)))

    # report
    r = sub.add_parser("report", help="Export findings to a report file")
    _common(r)
    r.add_argument("--format", default="html",
                   choices=["html", "json", "md", "markdown", "pdf"])
    r.add_argument("--target", metavar="LABEL",
                   help="Target label for the report header")
    r.set_defaults(func=_cmd_report)

    # findings
    fd = sub.add_parser("findings", help="List findings recorded in a workspace")
    _common(fd)
    fd.set_defaults(func=_cmd_findings)

    # workspaces
    ws = sub.add_parser("workspaces", help="List all workspaces")
    _common(ws)
    ws.set_defaults(func=_cmd_workspaces)

    # plugins
    pl = sub.add_parser("plugins", help="List loaded plugins & connectors")
    _common(pl)
    pl.set_defaults(func=_cmd_plugins)

    # dashboard
    db = sub.add_parser("dashboard", help="Launch the persistent Textual SOC dashboard")
    _common(db)
    db.add_argument("--passive", action="store_true")
    db.set_defaults(func=_cmd_dashboard)

    return p


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    """
    The single entry point for all invocation styles:

        spyder                → REPL (no subcommand)
        spyder scan ...       → one-shot CLI
        spyder --version      → version
        python3 -m spyder ... → same as above
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Imported here, not at module scope: --help/--version/argparse errors all
    # return above this point without paying for the Rich console.
    from rich.markup import escape

    from spyder.ui.theme import NEON_RED

    console = _console()

    # No subcommand → launch the interactive REPL
    if not args.command:
        try:
            _run_async(_run_repl(
                workspace=args.workspace,
                profile=args.profile,
                animate=not args.no_anim,
            ))
            return 0
        except KeyboardInterrupt:
            return 130
        except Exception as exc:
            console.print(f"[bold {NEON_RED}]error:[/] {escape(str(exc))}")
            return 1

    # Subcommand given → dispatch to its handler
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        console.print(f"\n[{NEON_RED}]interrupted[/]")
        return 130
    except Exception as exc:
        console.print(f"[bold {NEON_RED}]error:[/] {escape(str(exc))}")
        if getattr(args, "debug", False):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
