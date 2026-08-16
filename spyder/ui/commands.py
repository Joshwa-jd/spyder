"""Modular command system for the SPYDER interactive console.

Each command is a small object with a name, help text, and an async handler.
Commands are registered into a CommandRegistry and dispatched by the shell.
New commands (including from plugins) can be added without touching the shell.
"""
from __future__ import annotations

import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.markup import escape

from ..utils.logging import get_logger

log = get_logger("shell")

# A handler receives the shell context and parsed args, returns nothing.
Handler = Callable[["ShellContext", list[str]], Awaitable[None]]


@dataclass
class Command:
    name: str
    summary: str
    handler: Handler
    usage: str = ""
    aliases: tuple[str, ...] = ()
    category: str = "general"
    # Rich per-command help metadata (rendered by `help <command>`). All optional
    # so third-party/plugin commands stay a one-liner; built-ins fill these in.
    description: str = ""                       # longer prose than `summary`
    arguments: tuple[tuple[str, str], ...] = () # (name, meaning) pairs
    examples: tuple[str, ...] = ()              # example invocations
    related: tuple[str, ...] = ()               # names of related commands
    exit_codes: tuple[tuple[str, str], ...] = ()  # (code, meaning) pairs


class CommandRegistry:
    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}
        self._aliases: dict[str, str] = {}

    def register(self, command: Command) -> None:
        self._commands[command.name] = command
        for alias in command.aliases:
            self._aliases[alias] = command.name

    def resolve(self, name: str) -> Command | None:
        if name in self._commands:
            return self._commands[name]
        if name in self._aliases:
            return self._commands[self._aliases[name]]
        return None

    def all(self) -> list[Command]:
        return sorted(self._commands.values(), key=lambda c: (c.category, c.name))

    def names(self) -> list[str]:
        return list(self._commands) + list(self._aliases)

    def suggest(self, name: str, n: int = 3) -> list[str]:
        """Closest known command names to a mistyped one (for 'did you mean').

        Combines difflib fuzzy matches with prefix matches (so ``rep`` → ``replay``,
        ``report``) and returns canonical command names, most-relevant first.
        """
        import difflib

        candidates = list(self._commands) + list(self._aliases)
        close = difflib.get_close_matches(name, candidates, n=n, cutoff=0.6)
        prefix = [c for c in candidates if c.startswith(name) and c not in close]
        # Map any alias hits back to the canonical command name, de-duplicated.
        seen: dict[str, None] = {}
        for cand in close + prefix:
            canonical = self._aliases.get(cand, cand)
            seen.setdefault(canonical, None)
        return list(seen)[:n]

    async def dispatch(self, context: ShellContext, line: str) -> bool:
        """Parse and run a command line. Returns False if the shell should exit."""
        line = line.strip()
        if not line:
            return True
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        name, args = parts[0], parts[1:]
        cmd = self.resolve(name)
        if not cmd:
            from . import theme
            context.console.print(theme.err(f"unknown command: {escape(name)}"))
            suggestions = self.suggest(name)
            if suggestions:
                context.console.print(f"[dim]did you mean:[/] {', '.join(suggestions)}")
            context.console.print("[dim]type 'help' to list commands[/]")
            return True
        if name in ("exit", "quit"):
            return False
        try:
            await cmd.handler(context, args)
        except KeyboardInterrupt:
            context.console.print("[red]interrupted[/]")
        except Exception as exc:
            # A single command must never take down the console. Show a concise,
            # professional message; the full traceback goes to the debug log.
            context.console.print(f"[red]error:[/] {escape(str(exc))}")
            log.debug("command '%s' failed", name, exc_info=True)
        return True


# Imported lazily to avoid a cycle; ShellContext is defined in shell.py.
from typing import TYPE_CHECKING  # noqa: E402

if TYPE_CHECKING:
    from .shell import ShellContext
