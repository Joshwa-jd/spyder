"""Run the real SPYDER CLI — as a subprocess, and as a session on a real PTY.

Two things are checked here that in-process tests structurally cannot check:

  * **Exit codes.** A caller in a shell script or a CI job sees only the exit
    code, and an in-process test never produces one.
  * **Terminal state.** Whether the terminal is left usable after a full-screen
    app is a property of the bytes written to a tty. Off a tty, the code that
    writes them is deliberately a no-op, so a test that does not allocate a
    pty is testing the no-op.
"""
from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

#: CSI/OSC/charset escapes. Enough to turn a pty capture into the text a human
#: would read off the screen; not a terminal emulator.
_ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-B0-9]|\x1b[=>]|\x1b\][^\x07]*\x07")


def strip_ansi(data: bytes) -> str:
    return _ANSI.sub(b"", data).decode("utf-8", "replace")

#: Exit-code contract, as documented by the REPL's own `help exit`.
EXIT_OK = 0
EXIT_ERROR = 1        # handled runtime error — a message, never a traceback
EXIT_USAGE = 2        # argparse rejected the command line
EXIT_INTERRUPTED = 130  # SIGINT


@dataclass
class Result:
    """One completed CLI invocation."""

    args: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    @property
    def traceback(self) -> bool:
        """A traceback reaching the user is a bug regardless of the exit code."""
        return "Traceback (most recent call last)" in self.output


def _env(home: str | os.PathLike[str], **extra: str) -> dict[str, str]:
    return {
        **os.environ,
        "SPYDER_HOME": str(home),
        "NO_COLOR": "1",
        "TERM": "dumb",
        "COLUMNS": "100",
        **extra,
    }


def run_cli(*args: str, home: str | os.PathLike[str], timeout: float = 120.0) -> Result:
    """Invoke ``python -m spyder`` with a closed stdin, and capture everything.

    stdin is ``/dev/null`` so a command that unexpectedly waits for input fails
    as a timeout instead of hanging the caller forever.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "spyder", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env(home),
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return Result(args, None, "", "", timed_out=True)
    return Result(args, proc.returncode, proc.stdout, proc.stderr)


# --- pty ---------------------------------------------------------------------

#: Sequences the terminal owner (spyder.ui.terminal) must emit on teardown.
RESTORE_MARKERS = {
    "leave alternate screen": b"\x1b[?1049l",
    "show cursor": b"\x1b[?25h",
    "disable SGR mouse": b"\x1b[?1006l",
    "disable bracketed paste": b"\x1b[?2004l",
}


@dataclass
class Session:
    """A SPYDER process attached to a pseudo-terminal."""

    pid: int
    fd: int
    output: bytes = b""
    _closed: bool = field(default=False, repr=False)

    def read_for(self, seconds: float, until: bytes | None = None) -> bytes:
        """Accumulate output for up to ``seconds``, stopping early on ``until``."""
        end = time.monotonic() + seconds
        found = b""
        while time.monotonic() < end:
            readable, _, _ = select.select([self.fd], [], [], 0.2)
            if not readable:
                continue
            try:
                chunk = os.read(self.fd, 262144)
            except OSError:  # the child closed the pty
                break
            if not chunk:
                break
            self.output += chunk
            found += chunk
            if until and until in self.output:
                break
        return found

    @property
    def text(self) -> str:
        """Everything received so far, with the escape sequences stripped."""
        return strip_ansi(self.output)

    def send(self, data: bytes) -> None:
        os.write(self.fd, data)

    def send_line(self, line: str, settle: float = 3.0) -> str:
        """Type a command, press Enter, and return the text it produced."""
        self.send(line.encode() + b"\r")
        return strip_ansi(self.read_for(settle))

    def wait_for_prompt(self, seconds: float = 25.0) -> bool:
        """Block until the REPL prompt is on screen, then let it settle."""
        self.read_for(seconds, until=b"spyder(")
        self.read_for(0.6)
        return "spyder(" in self.text

    def resize(self, cols: int, rows: int) -> None:
        """Resize the window and deliver SIGWINCH, as a terminal emulator would."""
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.kill(self.pid, signal.SIGWINCH)

    def interrupt(self) -> None:
        os.kill(self.pid, signal.SIGINT)

    def wait(self, timeout: float = 20.0) -> tuple[str, int | None]:
        """``("exit", code)``, ``("signal", n)``, or ``("hung", None)``."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self._closed = True
                if os.WIFEXITED(status):
                    return "exit", os.WEXITSTATUS(status)
                return "signal", os.WTERMSIG(status)
            self.read_for(0.1)
        return "hung", None

    def restored(self, since: int = 0) -> dict[str, bool]:
        """Which terminal-restoration sequences were written after ``since``.

        ``since`` is an offset into :attr:`output`; pass ``len(session.output)``
        taken before the teardown so startup's own reset is not mistaken for it.
        """
        tail = self.output[since:]
        return {name: seq in tail for name, seq in RESTORE_MARKERS.items()}

    def kill(self) -> None:
        if not self._closed:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
            self._closed = True
        try:
            os.close(self.fd)
        except OSError:
            pass


def spawn_pty(
    *args: str, home: str | os.PathLike[str], cols: int = 110, rows: int = 32
) -> Session:
    """Start ``python -m spyder`` on its own pseudo-terminal."""
    pid, fd = pty.fork()
    if pid == 0:  # child — replaced by execve, so nothing here returns
        os.environ.update(
            _env(home, TERM="xterm-256color", COLUMNS=str(cols), LINES=str(rows))
        )
        os.environ.pop("NO_COLOR", None)
        os.chdir(str(ROOT))
        os.execv(sys.executable, [sys.executable, "-m", "spyder", *args])
        os._exit(127)  # unreachable
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    return Session(pid, fd)
