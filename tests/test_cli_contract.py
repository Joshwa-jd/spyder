"""Round 8: the CLI's observable contract — exit codes, and no traceback ever.

These invoke the real ``python -m spyder`` in a subprocess. That is slower than
calling the handlers directly, and it is the point: a caller in a shell script
sees an exit code and a stream of bytes, neither of which an in-process test
produces.
"""
from __future__ import annotations

import pytest

from verification.cli.harness import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    run_cli,
)
from verification.groundtruth.server import ground_truth_server


@pytest.fixture(scope="module")
def home(tmp_path_factory):
    return tmp_path_factory.mktemp("spyder-home")


@pytest.fixture(scope="module")
def target():
    with ground_truth_server() as base:
        yield base


# --- exit codes -------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ("--version",),
        ("--help",),
        ("scan", "--help"),
        ("crawl", "--help"),
        ("report", "--help"),
        ("connector", "--help"),
        ("findings", "--help"),
        ("workspaces", "--help"),
        ("plugins", "--help"),
        ("dashboard", "--help"),
    ],
)
def test_informational_commands_exit_zero(args, home):
    r = run_cli(*args, home=home, timeout=60)
    assert r.returncode == EXIT_OK, f"{args} → {r.returncode}\n{r.output[-800:]}"
    assert not r.traceback


@pytest.mark.parametrize(
    "args",
    [
        ("bogus-subcommand",),
        ("--no-such-flag",),
        ("scan",),                          # -u is required
        ("crawl",),
        ("connector",),                     # name and -u are required
        ("report", "--format", "xlsx"),     # not in choices
        ("scan", "-u", "http://x", "--format", "html"),  # wrong command's flag
    ],
)
def test_misuse_exits_two_and_prints_usage(args, home):
    """argparse's contract: 2 for a bad command line, with usage on stderr."""
    r = run_cli(*args, home=home, timeout=60)
    assert r.returncode == EXIT_USAGE, f"{args} → {r.returncode}\n{r.output[-800:]}"
    assert "usage:" in r.output.lower()
    assert not r.traceback


@pytest.mark.parametrize(
    "args,expected_message",
    [
        (("scan", "-u", "not a url"), "invalid target"),
        (("connector", "nosuchtool", "-u", "http://127.0.0.1:1"), "no connector named"),
    ],
)
def test_handled_runtime_errors_exit_one_with_a_message(args, expected_message, home):
    """A runtime failure is reported, not raised: exit 1 and a readable line."""
    r = run_cli(*args, home=home, timeout=90)
    assert r.returncode == EXIT_ERROR, f"{args} → {r.returncode}\n{r.output[-800:]}"
    assert expected_message in r.output.lower()
    assert not r.traceback, f"traceback leaked to the user:\n{r.output[-1500:]}"


def test_missing_profile_is_an_error_not_a_crash(home, tmp_path):
    r = run_cli("scan", "-u", "http://127.0.0.1:1", "--profile",
                str(tmp_path / "nope.yml"), home=home, timeout=90)
    assert r.returncode == EXIT_ERROR
    assert not r.traceback


def test_missing_profile_fails_the_same_way_for_every_subcommand(home, tmp_path):
    """A flag honoured by one command and ignored by another is a trap."""
    missing = str(tmp_path / "nope.yml")
    codes = {
        cmd: run_cli(cmd, "--profile", missing, home=home, timeout=90).returncode
        for cmd in ("workspaces", "plugins", "findings")
    }
    assert set(codes.values()) == {EXIT_ERROR}, codes


# --- real work --------------------------------------------------------------


def test_crawl_against_ground_truth_exits_zero(home, target):
    r = run_cli("crawl", "-u", target, "--no-anim", home=home, timeout=180)
    assert r.returncode == EXIT_OK, r.output[-1500:]
    assert not r.traceback
    assert "crawl completed" in r.output.lower()


def test_scan_against_ground_truth_exits_zero(home, target):
    r = run_cli("scan", "-u", target, "--no-anim", home=home, timeout=180)
    assert r.returncode == EXIT_OK, r.output[-1500:]
    assert not r.traceback
    assert "scan completed" in r.output.lower()


@pytest.mark.parametrize("fmt", ["json", "md", "html"])
def test_report_export_exits_zero(fmt, home, target):
    run_cli("crawl", "-u", target, "--no-anim", home=home, timeout=180)
    r = run_cli("report", "--format", fmt, home=home, timeout=120)
    assert r.returncode == EXIT_OK, r.output[-1500:]
    assert "report written" in r.output.lower()


def test_repeated_identical_commands_stay_successful(home, target):
    """Re-running must not accumulate state that eventually breaks a command."""
    for i in range(3):
        r = run_cli("crawl", "-u", target, "--no-anim", home=home, timeout=180)
        assert r.returncode == EXIT_OK, f"run {i + 1} → {r.returncode}\n{r.output[-800:]}"
        assert not r.traceback


def test_workspace_flag_before_the_subcommand_is_honoured(home, target):
    """``spyder -w acme crawl …`` must not be reset to the default workspace."""
    run_cli("-w", "acme-contract", "crawl", "-u", target, "--no-anim", home=home, timeout=180)
    r = run_cli("workspaces", home=home, timeout=90)
    assert r.returncode == EXIT_OK
    assert "acme-contract" in r.output
