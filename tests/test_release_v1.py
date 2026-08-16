"""Regression tests for the v1.0 release-hardening pass.

Each test here pins a defect that was found by auditing the shipped product and
reproduced before it was fixed, or an invariant the release depends on. They are
grouped by the property they protect, not by the module they touch.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import spyder
from spyder.__main__ import build_parser, main

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── Global flags must behave identically across every subcommand ──────────────
#
# `spyder --profile <missing> workspaces` used to exit 0 and print a workspace
# table: _cmd_workspaces called load_config() with no arguments, so it silently
# ignored --profile while every other subcommand raised "profile not found".
# A flag that one command honours and another discards is worse than an
# unsupported flag, because the operator gets no signal that it did nothing.

_PROFILE_AWARE_COMMANDS = ["scan", "crawl", "connector", "report", "findings",
                           "workspaces", "plugins", "dashboard"]


@pytest.mark.parametrize("command", _PROFILE_AWARE_COMMANDS)
def test_every_subcommand_accepts_the_global_flags(command):
    """-w / --profile are defined on every subcommand, not just some of them."""
    parser = build_parser()
    sub = parser._subparsers._group_actions[0].choices[command]  # type: ignore[union-attr]
    flags = {opt for action in sub._actions for opt in action.option_strings}
    assert {"-w", "--workspace"} <= flags, f"{command} is missing -w/--workspace"
    assert "--profile" in flags, f"{command} is missing --profile"


def test_workspaces_rejects_a_missing_profile(tmp_path, monkeypatch, capsys):
    """A mistyped --profile must fail the same way for `workspaces` as for `scan`."""
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    code = main(["--profile", str(tmp_path / "nope.yaml"), "workspaces"])
    assert code == 1
    assert "profile not found" in capsys.readouterr().out


def test_scan_rejects_a_missing_profile_the_same_way(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    code = main(["--profile", str(tmp_path / "nope.yaml"), "scan", "-u", "https://example.com"])
    assert code == 1
    assert "profile not found" in capsys.readouterr().out


def test_workspaces_accepts_a_valid_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    profile = tmp_path / "ok.yaml"
    profile.write_text("passive_mode: true\n")
    assert main(["--profile", str(profile), "workspaces"]) == 0


# ── CLI/REPL command parity ───────────────────────────────────────────────────
#
# `findings` existed only in the REPL, so a scripted user had to export a whole
# report just to see what a workspace held.

def test_findings_is_available_as_a_cli_subcommand(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    assert main(["-w", "acme", "findings"]) == 0
    assert "Findings" in capsys.readouterr().out


def test_findings_honours_a_workspace_given_before_the_subcommand(tmp_path, monkeypatch):
    """The pre-subcommand -w fix must cover newly added subcommands too."""
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    parser = build_parser()
    args = parser.parse_args(["-w", "acme", "findings"])
    assert args.workspace == "acme"


def test_repl_and_cli_expose_the_same_core_commands():
    """Commands meaningful outside an interactive session exist in both places."""
    from spyder.ui.builtins import register_builtins
    from spyder.ui.commands import CommandRegistry

    registry = CommandRegistry()
    register_builtins(registry)
    repl_commands = {c.name for c in registry.all()}

    parser = build_parser()
    cli_commands = set(parser._subparsers._group_actions[0].choices)  # type: ignore[union-attr]

    # `workspaces` is the CLI spelling of the REPL's `workspace list`.
    shared = {"scan", "crawl", "connector", "report", "findings", "plugins", "dashboard"}
    assert shared <= repl_commands, shared - repl_commands
    assert shared <= cli_commands, shared - cli_commands


# ── Startup cost ──────────────────────────────────────────────────────────────
#
# Building the parser used to import the orchestrator, HTTP stack, reporting
# engine and the whole Rich/Textual UI — ~625 ms of the ~700 ms that
# `spyder --version` took, on a path that touches none of it. This test pins the
# import surface rather than a wall-clock number so it cannot flake on a loaded
# CI runner.

_FORBIDDEN_AT_IMPORT = [
    "spyder.core.orchestrator",
    "spyder.reporting.engine",
    "spyder.ui.dashboard",
    "spyder.ui.shell",
    "httpx",
    "textual",
    "jinja2",
    "bs4",
]


def test_importing_the_entry_point_does_not_drag_in_the_framework():
    probe = (
        "import sys; import spyder.__main__; "
        f"loaded=[m for m in {_FORBIDDEN_AT_IMPORT!r} if m in sys.modules]; "
        "print(','.join(loaded))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True, text=True, check=True, cwd=REPO_ROOT,
    ).stdout.strip()
    assert out == "", (
        f"spyder.__main__ eagerly imports {out} — this is a ~10x startup "
        "regression for --help/--version. Import it inside the handler instead."
    )


def test_building_the_parser_does_not_drag_in_the_framework():
    probe = (
        "import sys; from spyder.__main__ import build_parser; build_parser(); "
        f"loaded=[m for m in {_FORBIDDEN_AT_IMPORT!r} if m in sys.modules]; "
        "print(','.join(loaded))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True, text=True, check=True, cwd=REPO_ROOT,
    ).stdout.strip()
    assert out == "", f"build_parser() eagerly imports {out}"


def test_version_and_help_still_work_after_the_lazy_import_split():
    for flag in ("--version", "--help"):
        proc = subprocess.run(
            [sys.executable, "-m", "spyder", flag],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip()


def test_version_output_reports_the_package_version():
    proc = subprocess.run(
        [sys.executable, "-m", "spyder", "--version"],
        capture_output=True, text=True, cwd=REPO_ROOT, check=True,
    )
    assert proc.stdout.strip() == f"SPYDER {spyder.__version__}"


# ── Version is single-sourced ─────────────────────────────────────────────────
#
# pyproject.toml used to carry a second hardcoded version. Two sources of truth
# for a version drift, and the one users see in `pip show` is the one that is
# wrong.

def test_pyproject_reads_the_version_from_the_package():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert 'dynamic = ["version"]' in pyproject
    assert 'version = { attr = "spyder.__version__" }' in pyproject
    assert not re.search(r'^version\s*=\s*"', pyproject, re.MULTILINE), (
        "pyproject.toml declares a static version — it must come from "
        "spyder.__version__ so the two cannot disagree"
    )


def test_version_is_a_release_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", spyder.__version__)


def test_changelog_documents_the_current_version():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
    assert f"## [{spyder.__version__}]" in changelog


def test_user_agent_carries_the_real_version():
    """The default UA hardcoded 'SPYDER/0.1' and never tracked releases."""
    from spyder.core.config import SpyderConfig

    ua = SpyderConfig().http.user_agents[0]
    assert f"SPYDER/{spyder.__version__}" in ua
    # Honest identification, not a spoofed browser: a target's operators must be
    # able to attribute the traffic.
    assert "authorized-testing" in ua


# ── Plugin discovery is transparent ───────────────────────────────────────────
#
# The README claimed the repository's own plugins/ directory was auto-loaded. It
# never was — only $SPYDER_HOME/plugins is scanned — so the shipped example
# plugin silently did nothing and there was no on-screen hint about where SPYDER
# actually looked.

def test_default_plugin_directory_is_under_spyder_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    from spyder.core.config import load_config

    cfg = load_config()
    assert cfg.default_plugin_dir in cfg.plugin_dirs
    assert cfg.default_plugin_dir == tmp_path / "plugins"


def test_configured_plugin_directories_are_scanned(tmp_path, monkeypatch):
    """The documented 'point plugin_dirs at your own directory' workflow works."""
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path / "home"))
    plugin_dir = tmp_path / "myplugins"
    plugin_dir.mkdir()
    (plugin_dir / "demo.py").write_text(
        "from typing import Any\n"
        "from spyder.core.models import Endpoint, Finding\n"
        "from spyder.plugins.framework import AnalyzerPlugin\n"
        "\n"
        "class DemoAnalyzer(AnalyzerPlugin):\n"
        "    name = 'demo-analyzer'\n"
        "    version = '1.0.0'\n"
        "    async def analyze(self, endpoints: list[Endpoint],\n"
        "                      context: dict[str, Any]) -> list[Finding]:\n"
        "        return []\n"
    )
    profile = tmp_path / "p.yaml"
    profile.write_text(f"plugin_dirs:\n  - {plugin_dir}\n")

    from spyder.core.config import load_config
    from spyder.core.orchestrator import Orchestrator

    cfg = load_config(profile)
    orch = Orchestrator(cfg, "default")
    try:
        assert "demo-analyzer" in orch.registry.analyzers
        assert plugin_dir in cfg.plugin_dirs
    finally:
        orch.close()


def test_plugins_command_names_every_directory_it_scanned(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    assert main(["plugins"]) == 0
    out = capsys.readouterr().out
    assert "Plugin directories scanned" in out
    # Rich wraps long paths, so match on the distinctive trailing segment.
    assert "plugins" in out


def test_a_broken_plugin_does_not_stop_startup(tmp_path, monkeypatch):
    """Third-party code must never take the framework down with it."""
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path / "home"))
    plugin_dir = tmp_path / "broken"
    plugin_dir.mkdir()
    (plugin_dir / "boom.py").write_text("raise RuntimeError('deliberately broken')\n")
    profile = tmp_path / "p.yaml"
    profile.write_text(f"plugin_dirs:\n  - {plugin_dir}\n")

    from spyder.core.config import load_config
    from spyder.core.orchestrator import Orchestrator

    orch = Orchestrator(load_config(profile), "default")
    try:
        assert orch.registry.connectors, "built-in connectors must still load"
    finally:
        orch.close()


# ── Exit codes are the documented contract ────────────────────────────────────

def test_exit_codes(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    assert main(["workspaces"]) == 0                                    # success
    assert main(["--profile", "/nonexistent.yaml", "plugins"]) == 1     # error

    # Bad arguments are argparse's job: exit 2, like every POSIX tool.
    with pytest.raises(SystemExit) as exc:
        main(["scan"])          # missing the required -u
    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc:
        main(["no-such-command"])
    assert exc.value.code == 2


def test_invalid_url_is_a_clean_error_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    assert main(["scan", "-u", "not a url"]) == 1
    out = capsys.readouterr().out
    assert "Invalid target" in out
    assert "Traceback" not in out


def test_unknown_connector_lists_the_available_ones(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    assert main(["connector", "nosuchtool", "-u", "https://example.com"]) == 1
    out = capsys.readouterr().out
    assert "No connector named" in out
    assert "nuclei" in out          # tells the operator what they *can* run
    assert "Traceback" not in out


# ── Packaging ─────────────────────────────────────────────────────────────────

def test_py_typed_marker_ships_with_the_package():
    """PEP 561: downstream plugin authors get our type hints."""
    assert (Path(spyder.__file__).parent / "py.typed").is_file()
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert '"spyder" = ["py.typed"]' in pyproject


def test_console_script_points_at_the_single_entry_point():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert 'spyder = "spyder.__main__:main"' in pyproject


def test_main_py_shim_delegates_to_the_same_entry_point():
    """`python main.py` must not be a second implementation."""
    source = (REPO_ROOT / "main.py").read_text()
    assert "from spyder.__main__ import main" in source


def test_repl_is_the_default_when_no_subcommand_is_given():
    args = build_parser().parse_args([])
    assert args.command is None
    assert args.workspace == "default"
