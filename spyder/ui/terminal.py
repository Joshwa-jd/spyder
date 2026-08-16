"""The single owner of terminal *screen control* for SPYDER.

Every byte that clears the screen or restores the terminal goes through this
module. Nothing else in the codebase may emit cursor-movement, alternate-screen,
or screen-clearing escape sequences. This is what makes the console behave
deterministically — like sqlmap / ffuf / nuclei / msfconsole — where the screen
is wiped exactly once per "fresh screen" event, always homing the cursor to row
1, column 1 so the banner (see ``spyder.ui.banner``) repaints from the top.

Public surface (the ONLY screen-control primitives the rest of the app may call):

    console                 the one Rich Console singleton
    restore()               force the terminal out of full-screen app mode
    clear()                 wipe screen + scrollback, home the cursor to (1,1)
    terminal_guard()        restore() even when the process is signalled to death

The banner itself lives in ``spyder.ui.banner`` (one implementation, no session
state), and ``banner.render_banner`` calls ``clear()`` here — so screen control
and banner content each have exactly one owner, with no overlap.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .theme import console

__all__ = ["console", "restore", "clear", "terminal_guard"]

# ── ANSI sequences — defined ONCE, nowhere else in the codebase ────────────────
#
# Restore: exit alternate screen · show cursor · disable every mouse-tracking
# mode · disable bracketed paste · reset SGR attributes. Issued after a
# full-screen (Textual) app so the REPL returns on a sane terminal.
_RESTORE_SEQ = (
    "\x1b[?1049l"  # leave alternate screen buffer
    "\x1b[?25h"    # show cursor
    "\x1b[?1000l"  # disable mouse click tracking
    "\x1b[?1002l"  # disable mouse drag tracking
    "\x1b[?1003l"  # disable mouse motion tracking
    "\x1b[?1006l"  # disable SGR mouse encoding
    "\x1b[?1015l"  # disable urxvt mouse encoding
    "\x1b[?2004l"  # disable bracketed paste
    "\x1b[0m"      # reset colours / attributes
)

# Clear: home the cursor (H) → clear the visible screen (2J) → clear the
# scrollback (3J). Home comes FIRST so the cursor is deterministically at
# (row 1, col 1) when clearing finishes; 2J and 3J do not move the cursor, so
# the next byte written lands at the top-left of a blank screen.
_CLEAR_SEQ = "\x1b[H\x1b[2J\x1b[3J"


def _raw_write(seq: str) -> None:
    """Write an escape sequence straight to the terminal's file descriptor.

    ``_write`` goes through ``sys.stdout``, which is the right thing everywhere
    except inside a signal handler that fires while a full-screen app is running:
    Textual swaps ``sys.stdout`` for a capture buffer so an app's stray ``print``
    cannot corrupt the screen, and restoration bytes written there land in the
    buffer and are discarded with it. ``sys.__stdout__`` is the interpreter's
    original stream and is not swapped, so its descriptor still refers to the
    terminal. ``os.write`` is also the safer primitive to call from a handler —
    no buffering, no reentrancy into the io stack.
    """
    try:
        stream = sys.__stdout__ if sys.__stdout__ is not None else sys.stdout
        fd = stream.fileno()
        if os.isatty(fd):
            os.write(fd, seq.encode("ascii", "ignore"))
    except Exception:
        pass


def _write(seq: str) -> bool:
    """Write a raw escape sequence to stdout if it is a real terminal.

    Returns True if it was written to a TTY, False otherwise (so callers can
    fall back to Rich's own clear for non-TTY / captured output).
    """
    try:
        if sys.stdout.isatty():
            sys.stdout.write(seq)
            sys.stdout.flush()
            return True
    except Exception:
        pass
    return False


def restore() -> None:
    """Force the terminal out of any full-screen application mode.

    The single terminal-restoration implementation. Called on dashboard exit and
    before every clear so a corrupted full-screen teardown can never leak
    alternate-screen / mouse / hidden-cursor state into the REPL.
    """
    _write(_RESTORE_SEQ)


#: Signals whose default disposition kills the process without unwinding the
#: stack. ``SIGINT`` is deliberately absent: Python already turns it into a
#: KeyboardInterrupt, so ``finally`` blocks run and the REPL can catch it.
_FATAL_SIGNALS = tuple(
    s for s in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGHUP", None))
    if s is not None
)


@contextmanager
def terminal_guard() -> Iterator[None]:
    """Restore the terminal even if the process is signalled to death.

    ``restore()`` in a ``finally`` covers a normal return and an exception, but
    neither is what happens on SIGTERM: the default disposition kills the process
    outright, so no ``finally`` runs. A full-screen (Textual) app killed that way
    leaves the terminal in the alternate screen with the cursor hidden and mouse
    reporting on — the shell the user drops back to is unusable until they blindly
    type ``reset``. ``pkill spyder``, a ``timeout`` wrapper, and a service manager
    stopping the unit all take that path.

    The handler restores the terminal, then re-raises the signal against itself
    with the default disposition back in place. Dying *by* the signal rather than
    calling ``sys.exit`` keeps the exit status honest: a parent still sees
    ``WIFSIGNALED``/``SIGTERM``, which is what a supervisor reads.

    Only the main thread may install signal handlers, so this is a no-op
    elsewhere — the caller still gets its ``finally``-based restore.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _handler(signum: int, _frame: object) -> None:
        _raw_write(_RESTORE_SEQ)
        signal.signal(signum, signal.SIG_DFL)
        signal.raise_signal(signum)

    previous: list[tuple[int, object]] = []
    try:
        for sig in _FATAL_SIGNALS:
            try:
                previous.append((sig, signal.signal(sig, _handler)))
            except (OSError, ValueError):  # not settable on this platform
                pass
        yield
    finally:
        for sig, old in previous:
            try:
                signal.signal(sig, old)  # type: ignore[arg-type]
            except (OSError, ValueError):
                pass


def clear() -> None:
    """Wipe the entire terminal (screen + scrollback) and home the cursor.

    The single clear implementation. Restores first (so a clear issued after a
    corrupted full-screen exit wipes the real screen, not a stale alternate one),
    then clears. On a non-TTY, falls back to Rich's clear so captured output and
    tests still behave.
    """
    restore()
    if not _write(_CLEAR_SEQ):
        console.clear()
