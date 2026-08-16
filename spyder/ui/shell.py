"""SPYDER interactive console — the hacker-style REPL.

Uses prompt_toolkit for history, tab-completion, and a styled `spyder>` prompt,
and Rich for all rendered output. The command system is modular: commands live
in a CommandRegistry and are dispatched here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from rich.console import Console

from ..core.config import SpyderConfig
from ..core.orchestrator import Orchestrator
from . import theme
from .banner import render_banner
from .builtins import register_builtins
from .commands import CommandRegistry
from .terminal import console, restore
from .theme import PROMPT_STYLE_DICT

_PROMPT_STYLE = Style.from_dict(PROMPT_STYLE_DICT)


@dataclass
class ShellContext:
    config: SpyderConfig
    orch: Orchestrator
    registry: CommandRegistry
    workspace: str
    console: Console = field(default_factory=lambda: console)
    last_target: str | None = None

    def switch_workspace(self, name: str) -> None:
        self.orch.close()
        self.orch = Orchestrator(self.config, name)
        self.workspace = name


def _completer(registry: CommandRegistry) -> NestedCompleter:
    mapping: dict[str, object] = {}
    for cmd in registry.all():
        if cmd.name == "workspace":
            mapping[cmd.name] = {"list": None, "use": None, "new": None}
        elif cmd.name == "connector":
            mapping[cmd.name] = {"nuclei": None, "sqlmap": None, "burp": None}
        elif cmd.name == "report":
            mapping[cmd.name] = {"html": None, "json": None, "md": None, "pdf": None}
        elif cmd.name == "set":
            mapping[cmd.name] = {"proxy": None, "passive": None, "rate": None}
        else:
            mapping[cmd.name] = None
    return NestedCompleter.from_nested_dict(mapping)


class _Aborted(Exception):
    """The operator interrupted a running command."""


async def _dispatch_interruptibly(registry: CommandRegistry, ctx: ShellContext, line: str) -> bool:
    """Run one command so that Ctrl+C aborts *it* rather than the whole session.

    While the prompt is up, prompt_toolkit holds the terminal in raw mode and turns
    Ctrl+C into a ``KeyboardInterrupt`` at the ``prompt_async`` call, which the loop
    above already handles. While a command runs, the terminal is back in canonical
    mode, so Ctrl+C arrives as a real SIGINT to the foreground process group.

    Python's default SIGINT handler raises KeyboardInterrupt wherever the
    interpreter happens to be — for a running event loop that is inside the
    selector, *not* inside the coroutine. ``asyncio.run`` then unwinds and re-raises
    out of the ``asyncio.run`` call itself, so a ``try`` around this dispatch never
    saw it and the interrupt escaped all the way to ``main()`` (exit 130), taking
    the operator's workspace, history, and settings with it.

    Registering the handler on the loop instead turns the signal into a plain
    cancellation of the one task that should be cancelled. The handler is installed
    only for the lifetime of the command: at the prompt, SIGINT must keep its
    default meaning so prompt_toolkit and the ``except KeyboardInterrupt`` above
    behave as before.
    """
    import asyncio
    import signal

    loop = asyncio.get_running_loop()
    task: asyncio.Task[bool] = asyncio.ensure_future(registry.dispatch(ctx, line))
    interrupted = False

    def _cancel() -> None:
        nonlocal interrupted
        interrupted = True
        task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, _cancel)
    except (NotImplementedError, RuntimeError, ValueError):
        # No loop-level signal handling on this platform/thread — fall back to the
        # previous behaviour rather than losing the command entirely.
        return await task

    try:
        return await task
    except asyncio.CancelledError:
        if interrupted:
            raise _Aborted from None
        raise
    except KeyboardInterrupt:  # raced in before the handler took effect
        raise _Aborted from None
    finally:
        # Hands SIGINT back to Python's default handler, which is what the prompt
        # and the outer KeyboardInterrupt guard rely on.
        loop.remove_signal_handler(signal.SIGINT)


async def run_console(config: SpyderConfig, workspace: str = "default", animate: bool = True) -> None:
    registry = CommandRegistry()
    register_builtins(registry)
    orch = Orchestrator(config, workspace)
    ctx = ShellContext(config=config, orch=orch, registry=registry, workspace=workspace)

    # Single fresh-screen paint: identical to the `clear` command and dashboard
    # exit. `animate` only decides whether we wipe the screen first (a launch
    # inside an existing session — e.g. tests — may want the banner in place).
    render_banner(console, clear_first=animate)

    history_file = config.home / "logs" / ".console_history"
    session: PromptSession = PromptSession(
        history=FileHistory(str(history_file)),
        completer=_completer(registry),
        complete_while_typing=True,
        # prompt_toolkit reserves 8 blank lines below the prompt by default so the
        # tab-completion dropdown never scrolls the screen. That reservation is what
        # left a block of empty rows between each command's output and the next
        # prompt. Setting it to 0 makes the completion menu render inline (as GNU
        # readline / sqlmap / nuclei do) so the prompt sits flush under the output.
        reserve_space_for_menu=0,
        style=_PROMPT_STYLE,
    )

    def prompt_fragments():
        # spyder · <profile> (<workspace>) [passive] >
        # profile is shown only when it isn't the default, to stay uncluttered;
        # the mode segment reflects live scan state (passive vs active probing).
        frags = [("class:prompt.spyder", "spyder")]
        profile = ctx.config.profile_name
        if profile and profile != "default":
            frags.append(("class:prompt.profile", f":{profile}"))
        frags.append(("class:prompt.ws", f"({ctx.workspace})"))
        if ctx.orch.config.passive_mode:
            frags.append(("class:prompt.mode", " [passive]"))
        frags.append(("class:prompt.arrow", "> "))
        return frags

    try:
        while True:
            try:
                line = await session.prompt_async(prompt_fragments)
            except KeyboardInterrupt:
                # Ctrl+C cancels the current input line and stays in the REPL —
                # exactly like msfconsole / sqlmap. Use Ctrl+D or `exit` to leave.
                continue
            except EOFError:
                # Ctrl+D → end of input → leave the console.
                console.print(theme.info("closing console…"))
                break
            try:
                keep_going = await _dispatch_interruptibly(registry, ctx, line)
            except _Aborted:
                # restore() first: the command may have died mid-spinner, or inside
                # a full-screen app that had not yet installed its own handler.
                restore()
                console.print(theme.warn("aborted — returned to console"))
                continue
            if not keep_going:
                break
    finally:
        ctx.orch.close()
