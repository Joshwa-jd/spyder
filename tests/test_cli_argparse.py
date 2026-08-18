"""Regression tests for CLI argument parsing (PAT findings).

Guards two reproduced defects:
  * global flags (-w/--profile/--no-anim) placed BEFORE the subcommand were
    silently reset to the subparser default (data routed to the wrong workspace);
  * a mistyped --profile path was silently ignored / raised a raw OSError.
"""
from __future__ import annotations

import pytest

from spyder.__main__ import build_parser
from spyder.core.config import SpyderConfig


@pytest.mark.parametrize("argv,expected", [
    (["-w", "acme", "scan", "-u", "http://x"], "acme"),   # before subcommand
    (["scan", "-u", "http://x", "-w", "acme"], "acme"),    # after subcommand
    (["scan", "-u", "http://x"], "default"),               # neither -> default
    (["-w", "acme", "report"], "acme"),                    # report (no _common)
    (["-w", "acme", "crawl", "-u", "http://x"], "acme"),
    (["-w", "acme", "connector", "nuclei", "-u", "http://x"], "acme"),
])
def test_workspace_flag_survives_before_subcommand(argv, expected):
    args = build_parser().parse_args(argv)
    assert args.workspace == expected


@pytest.mark.parametrize("argv,expected", [
    (["--profile", "p.yaml", "plugins"], "p.yaml"),        # before subcommand
    (["plugins", "--profile", "p.yaml"], "p.yaml"),        # after subcommand
    (["plugins"], None),                                    # neither -> None
])
def test_profile_flag_survives_before_subcommand(argv, expected):
    args = build_parser().parse_args(argv)
    assert getattr(args, "profile", None) == expected


def test_no_anim_flag_survives_before_subcommand():
    args = build_parser().parse_args(["--no-anim", "scan", "-u", "http://x"])
    assert getattr(args, "no_anim", False) is True


def test_missing_profile_raises_clean_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError, match="profile not found"):
        SpyderConfig.from_profile(tmp_path / "nope.yaml")


def test_invalid_yaml_profile_raises_clean_valueerror(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("http: [unclosed\n")
    with pytest.raises(ValueError, match="invalid YAML"):
        SpyderConfig.from_profile(bad)


def test_valid_profile_loads(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text("passive_mode: true\n")
    cfg = SpyderConfig.from_profile(good)
    assert cfg.passive_mode is True
