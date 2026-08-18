"""Round 8: the REPL as an operator actually meets it — on a real terminal.

Everything here allocates a pty and drives ``python -m spyder`` through it. That
is deliberate and it is the only way these properties are observable:

  * The interrupt behaviour differs by terminal mode. At the prompt,
    prompt_toolkit holds the terminal in raw mode and turns Ctrl+C into a
    ``KeyboardInterrupt`` at the call site. While a command runs, the terminal is
    in canonical mode and Ctrl+C is a real SIGINT to the foreground process
    group, delivered wherever the interpreter happens to be. Only the first case
    is reachable without a pty, and only the second was broken.
  * Terminal restoration is a property of bytes written to a tty. Off a tty the
    code that writes them is a deliberate no-op, so a test that does not allocate
    a pty is asserting against the no-op.

These are slower than in-process tests. They are marked ``pty`` so they can be
deselected, but they are part of the default run: the defects they cover
(ISSUE-801, ISSUE-802) were both invisible to a green in-process suite.
"""
from __future__ import annotations

import os
import signal
import time

import pytest

from verification.cli.harness import spawn_pty, strip_ansi

pytestmark = pytest.mark.pty

#: Routable but dead — a request to it hangs rather than failing fast, which is
#: what makes a command long enough to interrupt on purpose.
UNREACHABLE = "http://10.255.255.1/"


@pytest.fixture
def repl(tmp_path):
    """A REPL sitting at its first prompt."""
    session = spawn_pty(home=tmp_path)
    assert session.wait_for_prompt(), f"REPL never reached a prompt:\n{session.text[-1500:]}"
    yield session
    session.kill()


def _exit_cleanly(session) -> tuple[str, int | None]:
    session.send(b"exit\r")
    return session.wait(timeout=25)


# --- the session survives what it promises to survive -------------------------


def test_ctrl_c_at_an_idle_prompt_does_not_exit(repl):
    repl.interrupt()
    repl.read_for(3.0)
    assert repl.wait(timeout=2.0)[0] == "hung", "Ctrl+C at the prompt exited the console"
    assert _exit_cleanly(repl) == ("exit", 0)


@pytest.mark.parametrize("command", ["scan", "crawl"])
def test_ctrl_c_during_a_running_command_aborts_it_and_keeps_the_session(command, repl):
    """ISSUE-802. The msfconsole contract the shell documents for itself.

    Before the fix this killed the whole console with exit 130 — one Ctrl+C aimed
    at a slow scan discarded the operator's workspace, history, and settings.
    """
    repl.send(f"{command} {UNREACHABLE}\r".encode())
    repl.read_for(1.5)  # let it get properly under way
    repl.interrupt()
    repl.read_for(6.0)

    assert repl.wait(timeout=3.0)[0] == "hung", (
        f"Ctrl+C during `{command}` killed the console:\n{repl.text[-1200:]}"
    )
    assert "aborted" in repl.text.lower(), "no abort message; the operator is guessing"
    assert "Traceback" not in repl.text
    assert _exit_cleanly(repl) == ("exit", 0), "console unusable after an abort"


def test_the_workspace_survives_an_aborted_command(repl):
    """An abort must cost the operator the command, not the session's context."""
    repl.send_line("workspace new acme", settle=4.0)
    repl.send(f"scan {UNREACHABLE}\r".encode())
    repl.read_for(1.5)
    repl.interrupt()
    repl.read_for(5.0)

    after = repl.send_line("workspace list", settle=6.0)
    assert "acme" in after, f"workspace lost after an abort:\n{after[-800:]}"
    assert _exit_cleanly(repl) == ("exit", 0)


def test_a_command_still_works_after_an_abort(repl):
    repl.send(f"crawl {UNREACHABLE}\r".encode())
    repl.read_for(1.5)
    repl.interrupt()
    repl.read_for(5.0)
    out = repl.send_line("help", settle=6.0)
    assert "Command" in out or "Recon" in out, f"REPL not usable after abort:\n{out[-800:]}"
    assert _exit_cleanly(repl) == ("exit", 0)


# --- leaving --------------------------------------------------------------


def test_exit_returns_zero(repl):
    assert _exit_cleanly(repl) == ("exit", 0)


def test_ctrl_d_closes_the_console_with_zero(repl):
    repl.send(b"\x04")
    repl.read_for(4.0)
    assert repl.wait(timeout=20) == ("exit", 0)
    assert "closing console" in repl.text.lower()


def test_sigterm_at_the_prompt_terminates(repl):
    os.kill(repl.pid, signal.SIGTERM)
    assert repl.wait(timeout=20)[0] in {"signal", "exit"}


# --- commands run, and never traceback ----------------------------------------


@pytest.mark.parametrize(
    "command,expected",
    [
        ("help", "Command"),
        ("help scan", "scan"),
        ("workspace list", "Workspaces"),
        ("plugins", "Plugins"),
        ("findings", "Findings"),
        ("history", "history"),
        ("set passive on", "passive"),
    ],
)
def test_repl_command_produces_output_without_a_traceback(command, expected, repl):
    out = repl.send_line(command, settle=6.0)
    assert "Traceback" not in out, f"`{command}` raised at the user:\n{out[-1200:]}"
    assert expected.lower() in out.lower(), f"`{command}` printed nothing recognisable:\n{out[-800:]}"


def test_an_unknown_command_suggests_and_does_not_exit(repl):
    out = repl.send_line("scna", settle=5.0)
    assert "unknown command" in out.lower()
    assert "did you mean" in out.lower() and "scan" in out
    assert _exit_cleanly(repl) == ("exit", 0)


@pytest.mark.parametrize("prefix,completion", [("work", "workspace"), ("conn", "connector")])
def test_tab_completes_a_command_prefix(prefix, completion, repl):
    """Autocomplete is a real keystroke against a real terminal or it is nothing."""
    repl.send(prefix.encode())
    repl.read_for(1.0)
    repl.send(b"\t")
    out = repl.read_for(3.0)
    # The terminal only echoes the *suffix* the completion added, wrapped in the
    # cursor/wrap escapes prompt_toolkit uses to redraw the line — so the check is
    # prefix + what was echoed, with the escapes stripped rather than the ESC
    # bytes alone removed (that leaves the CSI bodies interleaved in the text).
    typed = prefix + strip_ansi(out)
    assert completion in typed, (
        f"TAB after {prefix!r} did not complete to {completion!r}: {out!r}"
    )
    repl.send(b"\x15")  # Ctrl+U — clear the line so `exit` is not appended to it
    repl.read_for(1.0)
    assert _exit_cleanly(repl) == ("exit", 0)


# --- terminal geometry --------------------------------------------------------


def test_the_repl_survives_being_resized(repl):
    for cols, rows in [(60, 20), (200, 60), (100, 30)]:
        repl.resize(cols, rows)
        time.sleep(0.3)
    repl.read_for(1.5)
    out = repl.send_line("help", settle=6.0)
    assert "Traceback" not in repl.text
    assert "Command" in out or "Recon" in out
    assert _exit_cleanly(repl) == ("exit", 0)
