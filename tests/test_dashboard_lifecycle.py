"""Dashboard and terminal-state lifecycle.

The dashboard is the one place SPYDER takes over the whole terminal, so it is the
one place that can leave an operator with a corrupted shell — no cursor, mouse
reporting still on, or stuck in the alternate screen buffer. These tests cover
what can be checked without a human at a TTY: that every documented exit key
quits, that repeated launches stay clean, that resizes do not crash, and that the
restore sequence is complete.

A genuine interactive TTY session is still verified by hand before a release; see
the release checklist.
"""
from __future__ import annotations

import io
import sys
from unittest.mock import patch

import pytest

from spyder.core.config import SpyderConfig
from spyder.ui.dashboard import SpyderDashboard


@pytest.fixture
def isolated_config(tmp_path):
    cfg = SpyderConfig(home=tmp_path)
    cfg.ensure_dirs()
    return cfg


# ── Exit keys ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("key", ["ctrl+c", "ctrl+q"])
@pytest.mark.parametrize("size", [(80, 24), (200, 60), (40, 12)])
async def test_documented_exit_keys_quit_at_any_terminal_size(isolated_config, key, size):
    """Both keys are documented as 'return to console' — neither may hang.

    Textual binds ctrl+c to a quit *prompt* by default, which would strand an
    operator who expects the sqlmap/nuclei convention of Ctrl+C meaning stop.
    """
    app = SpyderDashboard(isolated_config, workspace="ws", profile="default")
    async with app.run_test(size=size) as pilot:
        await pilot.press(key)
        await pilot.pause()
    assert app.is_running is False, f"{key} at {size} did not quit the dashboard"


def test_exit_keys_are_bound_with_priority():
    """Priority binding is what stops Textual's default ctrl+c prompt winning."""
    bindings = {
        b.key: b
        for b in SpyderDashboard.BINDINGS
        if hasattr(b, "key")
    }
    for key in ("ctrl+c", "ctrl+q"):
        assert key in bindings, f"{key} is documented but not bound"
        assert bindings[key].action == "quit"
        assert bindings[key].priority is True


# ── Repeated launches ─────────────────────────────────────────────────────────

async def test_many_sequential_launches_stay_clean(isolated_config):
    """Widget-id collisions and leaked state only show up after several launches."""
    for _ in range(5):
        app = SpyderDashboard(isolated_config, workspace="ws", profile="default")
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
        assert app.is_running is False


# ── Resize ────────────────────────────────────────────────────────────────────

async def test_resizing_while_mounted_does_not_crash(isolated_config):
    app = SpyderDashboard(isolated_config, workspace="ws", profile="default")
    async with app.run_test(size=(80, 24)) as pilot:
        for width, height in ((120, 40), (60, 18), (200, 50), (80, 24)):
            app.console.size = (width, height)
            await pilot.pause()
        assert app.is_running is True
        await pilot.press("ctrl+c")
        await pilot.pause()
    assert app.is_running is False


# ── Terminal restoration ──────────────────────────────────────────────────────

def _captured_terminal_output(*calls) -> str:
    """Run terminal primitives against a fake TTY and return the bytes written."""
    import spyder.ui.terminal as terminal

    buf = io.StringIO()
    buf.isatty = lambda: True  # type: ignore[method-assign]
    with patch.object(sys, "stdout", buf):
        for call in calls:
            getattr(terminal, call)()
    return buf.getvalue()


@pytest.mark.parametrize(
    ("sequence", "what"),
    [
        ("\x1b[?1049l", "leave the alternate screen buffer"),
        ("\x1b[?25h", "show the cursor"),
        ("\x1b[?1000l", "disable mouse click tracking"),
        ("\x1b[?1002l", "disable mouse drag tracking"),
        ("\x1b[?1003l", "disable mouse motion tracking"),
        ("\x1b[?1006l", "disable SGR mouse encoding"),
        ("\x1b[?2004l", "disable bracketed paste"),
        ("\x1b[0m", "reset colours and attributes"),
    ],
)
def test_restore_emits_every_part_of_the_reset(sequence, what):
    assert sequence in _captured_terminal_output("restore"), (
        f"restore() must {what} — otherwise the state leaks into the operator's shell"
    )


def test_clear_restores_first_then_homes_the_cursor():
    """Order matters: clearing a stale alternate screen would wipe the wrong buffer."""
    out = _captured_terminal_output("clear")
    assert "\x1b[?1049l" in out
    assert out.index("\x1b[?1049l") < out.index("\x1b[H")
    # Home before erase, so the next byte lands at row 1 col 1 of a blank screen.
    assert out.index("\x1b[H") < out.index("\x1b[2J")
    assert "\x1b[3J" in out, "scrollback must be cleared too"


def test_terminal_control_is_a_no_op_off_a_tty():
    """Piped output and captured test output must not receive escape bytes."""
    import spyder.ui.terminal as terminal

    buf = io.StringIO()
    buf.isatty = lambda: False  # type: ignore[method-assign]
    with patch.object(sys, "stdout", buf):
        terminal.restore()
    assert buf.getvalue() == ""


def test_terminal_module_is_the_only_owner_of_screen_control():
    """No second code path may emit clear/alt-screen sequences."""
    from pathlib import Path

    pkg = Path(__file__).resolve().parent.parent / "spyder"
    offenders = []
    for path in pkg.rglob("*.py"):
        if path.name == "terminal.py":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if r"\x1b[2J" in line or r"\x1b[?1049" in line or r"\x1b[3J" in line:
                offenders.append(f"{path.relative_to(pkg.parent)}:{lineno}")
    assert not offenders, (
        "screen control must live only in spyder/ui/terminal.py: " + ", ".join(offenders)
    )
