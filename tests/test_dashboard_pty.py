"""Round 8: the dashboard on a real terminal — launch, exit, and how it is killed.

The property under test is what the *terminal* looks like afterwards. A
full-screen app that exits without leaving the alternate screen and re-showing
the cursor hands the operator a shell they cannot see themselves type in; the
usual recovery is to blindly type ``reset``. None of that is observable off a
tty, because the code that writes the restoration bytes is a no-op there.
"""
from __future__ import annotations

import os
import signal
import time

import pytest

from verification.cli.harness import spawn_pty, strip_ansi

pytestmark = pytest.mark.pty

#: Painted by the dashboard itself, so it cannot match the REPL banner that is
#: already on screen — the distinction matters, see the launch-race note below.
DASHBOARD_MARK = b"LIVE EVENT STREAM"


def _launch_cli_dashboard(home, timeout: float = 40.0):
    session = spawn_pty("dashboard", home=home)
    session.read_for(timeout, until=DASHBOARD_MARK)
    assert DASHBOARD_MARK in session.output, (
        f"dashboard never painted:\n{session.text[-1500:]}"
    )
    time.sleep(1.0)
    session.read_for(0.5)
    return session


def test_dashboard_launches_and_paints_its_header(tmp_path):
    s = _launch_cli_dashboard(tmp_path)
    try:
        assert "SPYDER" in s.text
        assert "ws default" in s.text, "header does not name the workspace"
        assert "Traceback" not in s.text
    finally:
        s.kill()


def test_ctrl_c_exits_the_dashboard_cleanly_and_restores_the_terminal(tmp_path):
    s = _launch_cli_dashboard(tmp_path)
    try:
        mark = len(s.output)
        s.interrupt()
        s.read_for(8.0)
        assert s.wait(timeout=25) == ("exit", 0)
        missing = [n for n, ok in s.restored(since=mark).items() if not ok]
        assert not missing, f"terminal left unrestored after Ctrl+C: {missing}"
    finally:
        s.kill()


def test_sigterm_during_the_dashboard_restores_the_terminal(tmp_path):
    """ISSUE-801.

    ``restore()`` sits in a ``finally``, which covers a normal return and an
    exception — but SIGTERM's default disposition kills the process without
    unwinding, so no ``finally`` ran and the terminal was left in the alternate
    screen with the cursor hidden. ``pkill spyder``, a ``timeout`` wrapper, and a
    service manager stopping the unit all take exactly that path.
    """
    s = _launch_cli_dashboard(tmp_path)
    try:
        mark = len(s.output)
        os.kill(s.pid, signal.SIGTERM)
        s.read_for(6.0)
        status = s.wait(timeout=25)

        tail = s.output[mark:]
        assert b"\x1b[?1049l" in tail, "terminal left in the alternate screen after SIGTERM"
        assert b"\x1b[?25h" in tail, "cursor left hidden after SIGTERM"
        # Cleaning up must not disguise how the process died: a supervisor reads
        # WIFSIGNALED, so the handler re-raises rather than calling sys.exit.
        assert status == ("signal", int(signal.SIGTERM)), status
    finally:
        s.kill()


def test_repeated_launch_and_exit_cycles_stay_clean(tmp_path):
    """Launching the dashboard repeatedly must not degrade or leak state."""
    for cycle in range(3):
        s = _launch_cli_dashboard(tmp_path / f"c{cycle}")
        try:
            mark = len(s.output)
            s.interrupt()
            s.read_for(8.0)
            assert s.wait(timeout=25) == ("exit", 0), f"cycle {cycle}"
            assert "Traceback" not in s.text, f"cycle {cycle}"
            missing = [n for n, ok in s.restored(since=mark).items() if not ok]
            assert not missing, f"cycle {cycle}: unrestored {missing}"
        finally:
            s.kill()


def test_dashboard_from_inside_the_repl_returns_to_the_console(tmp_path):
    """`help dashboard` promises Ctrl+C returns you to the console. It must."""
    s = spawn_pty(home=tmp_path)
    try:
        assert s.wait_for_prompt()
        s.send(b"dashboard\r")
        s.read_for(40.0, until=DASHBOARD_MARK)
        assert DASHBOARD_MARK in s.output, f"dashboard never painted:\n{s.text[-1200:]}"
        time.sleep(1.5)
        s.read_for(0.5)

        s.interrupt()
        out = strip_ansi(s.read_for(10.0))  # read_for returns raw bytes
        assert s.wait(timeout=3.0)[0] == "hung", "Ctrl+C left the console instead of the dashboard"
        assert "returned to console" in out.lower(), (
            f"no confirmation the console is back:\n{out[-600:]}"
        )
        s.send(b"exit\r")
        assert s.wait(timeout=25) == ("exit", 0)
    finally:
        s.kill()


def _leave_and_exit(s) -> tuple[str, int | None]:
    """Get back to a console prompt from wherever we are, then exit.

    Where an interrupt lands depends on how far the launch had progressed, so a
    test that asserts on the session's survival must not also assume the
    dashboard is already gone: keystrokes sent to a live full-screen app go into
    *its* input widget, not to the REPL. Interrupt until a prompt is on screen,
    then leave.
    """
    for _ in range(3):
        if s.text.rstrip().endswith(">") or "returned to console" in s.text.lower():
            break
        s.interrupt()
        s.read_for(5.0)
    s.send(b"exit\r")
    return s.wait(timeout=25)


@pytest.mark.parametrize("delay", [0.0, 0.4, 1.2])
def test_an_interrupt_during_dashboard_launch_never_kills_the_session(delay, tmp_path):
    """Ctrl+C while the dashboard is coming up — a guard, not a regression test.

    ISSUE-802 (an interrupt during a running command killing the whole console)
    was suspected to reach this path too, since the interrupt can arrive before
    the full-screen app installs its own handler. It does not: measured against
    the pre-fix code, all three delays below already passed, because
    ``_cmd_dashboard`` has always caught ``KeyboardInterrupt`` itself. The tests
    that actually reproduce ISSUE-802 are the ``scan``/``crawl`` aborts in
    ``test_repl_pty.py``. This one is kept as a guard over a path with no other
    coverage, and is deliberately not credited with the defect.

    How long the app takes to paint depends on machine load, so *where* an
    interrupt lands cannot be pinned by sleeping for a chosen number of
    milliseconds; an earlier version of this test asserted the app had not yet
    painted at 0.3 s and failed on an idle box, which was the test guessing
    rather than the product misbehaving. The delays here bracket the launch
    instead of pinpointing it, and what is asserted is the invariant that must
    hold wherever the signal lands: the console is alive, no traceback reached
    the user, and the session is still usable afterwards.

    At ``delay == 0`` the app provably cannot have painted yet, which is what
    keeps the pre-paint window genuinely covered rather than covered by luck.
    """
    s = spawn_pty(home=tmp_path)
    try:
        assert s.wait_for_prompt()
        s.send(b"dashboard\r")
        if delay:
            s.read_for(delay)
        painted_before_interrupt = DASHBOARD_MARK in s.output
        s.interrupt()
        s.read_for(8.0)

        if delay == 0.0:
            assert not painted_before_interrupt, (
                "the dashboard painted before an immediate interrupt — this case "
                "no longer covers the pre-paint window"
            )
        assert s.wait(timeout=3.0)[0] == "hung", (
            f"an interrupt {delay}s into launch killed the console:\n{s.text[-1200:]}"
        )
        assert "Traceback" not in s.text
        assert _leave_and_exit(s) == ("exit", 0), "console unusable afterwards"
    finally:
        s.kill()
