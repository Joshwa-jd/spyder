"""Documentation must describe the software that actually shipped.

The v1.0 audit found the README claiming a plugin-discovery behaviour that had
never existed. Prose drifts silently; these tests make it fail loudly. Every
command, flag, format, and file path referenced in the docs is checked against
the real parser, the real command registry, and the real filesystem.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from spyder.__main__ import build_parser
from spyder.ui.builtins import register_builtins
from spyder.ui.commands import CommandRegistry

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"
SECURITY = REPO_ROOT / "SECURITY.md"
CODE_OF_CONDUCT = REPO_ROOT / "CODE_OF_CONDUCT.md"
LICENSE = REPO_ROOT / "LICENSE"

ALL_DOCS = [README, CHANGELOG, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT] + sorted(
    DOCS_DIR.glob("*.md")
)


def _cli_commands() -> set[str]:
    parser = build_parser()
    return set(parser._subparsers._group_actions[0].choices)  # type: ignore[union-attr]


def _repl_commands() -> set[str]:
    registry = CommandRegistry()
    register_builtins(registry)
    names = set()
    for cmd in registry.all():
        names.add(cmd.name)
        names.update(cmd.aliases)
    return names


# ── The documents a public repository is expected to have ─────────────────────

@pytest.mark.parametrize(
    "path",
    [README, CHANGELOG, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, LICENSE,
     DOCS_DIR / "INSTALL.md",
     DOCS_DIR / "QUICKSTART.md",
     DOCS_DIR / "ARCHITECTURE.md",
     DOCS_DIR / "PLUGIN_DEVELOPMENT.md",
     DOCS_DIR / "MIGRATION.md"],
    ids=lambda p: p.name,
)
def test_required_document_exists_and_is_substantive(path):
    assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing"
    assert len(path.read_text().strip()) > 400, f"{path.name} is a stub"


@pytest.mark.parametrize(
    "path",
    [REPO_ROOT / ".github" / "workflows" / "ci.yml",
     REPO_ROOT / ".github" / "workflows" / "codeql.yml",
     REPO_ROOT / ".github" / "workflows" / "release.yml",
     REPO_ROOT / ".github" / "dependabot.yml",
     REPO_ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
     REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml",
     REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml",
     REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"],
    ids=lambda p: p.name,
)
def test_github_infrastructure_file_exists(path):
    assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing"


def test_all_github_yaml_parses():
    yaml = pytest.importorskip("yaml")
    for path in (REPO_ROOT / ".github").rglob("*.yml"):
        yaml.safe_load(path.read_text())


# ── README structure ──────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "heading",
    ["What is SPYDER?", "Features", "Installation", "Quick Start", "Screenshots",
     "Example workflows", "Commands", "Architecture", "Plugin system",
     "Configuration", "Development", "Roadmap", "FAQ", "Contributing", "Legal"],
)
def test_readme_covers_expected_section(heading):
    assert f"## {heading}" in README.read_text(), f"README is missing '## {heading}'"


# ── Documented commands must exist ────────────────────────────────────────────

def test_every_cli_subcommand_documented_in_the_readme_is_real():
    """Parse `spyder <word>` out of the README and check the parser knows it."""
    text = README.read_text()
    known = _cli_commands()
    # Flags, not subcommands, plus the bare REPL invocation.
    ignore = {"--version", "--help", "-w", "--profile", "--no-anim", "--debug"}
    documented = {
        m.group(1) for m in re.finditer(r"^\s*spyder\s+([a-z][a-z-]+)", text, re.MULTILINE)
    } - ignore
    unknown = documented - known
    assert not unknown, f"README documents non-existent CLI subcommands: {sorted(unknown)}"


def test_every_cli_subcommand_is_documented_in_the_readme():
    """The other direction: a shipped command nobody documented is also a bug."""
    text = README.read_text()
    undocumented = {c for c in _cli_commands() if c not in text}
    assert not undocumented, f"CLI subcommands missing from the README: {sorted(undocumented)}"


def test_readme_console_command_block_matches_the_registry():
    """The console command list must not name commands the REPL does not have."""
    text = README.read_text()
    block = text.split("### Console")[1].split("```")[1]
    known = _repl_commands()
    documented = {
        m.group(1) for m in re.finditer(r"^([a-z]+)", block, re.MULTILINE)
    }
    unknown = documented - known
    assert not unknown, f"README documents non-existent console commands: {sorted(unknown)}"


def test_quickstart_only_uses_real_commands():
    text = (DOCS_DIR / "QUICKSTART.md").read_text()
    known = _cli_commands() | _repl_commands()
    ignore = {"--version", "--help"}
    used = {
        m.group(1)
        for m in re.finditer(r"^\s*(?:spyder\((?:\w+)\)>|\$?\s*spyder)\s+([a-z][a-z-]+)",
                             text, re.MULTILINE)
    } - ignore
    unknown = used - known
    assert not unknown, f"QUICKSTART uses non-existent commands: {sorted(unknown)}"


def test_documented_report_formats_are_accepted_by_the_parser():
    parser = build_parser()
    report = parser._subparsers._group_actions[0].choices["report"]  # type: ignore[union-attr]
    fmt = next(a for a in report._actions if "--format" in a.option_strings)
    assert set(fmt.choices) >= {"html", "json", "md", "pdf"}
    for documented in ("html", "json", "md", "pdf"):
        assert documented in README.read_text()


def test_documented_exit_codes_match_the_implementation():
    """0 / 1 / 2 / 130 are stated in the README, QUICKSTART, and REPL help."""
    for path in (README, DOCS_DIR / "QUICKSTART.md"):
        text = path.read_text()
        assert "130" in text and "interrupt" in text.lower(), path.name

    registry = CommandRegistry()
    register_builtins(registry)
    scan = registry.resolve("scan")
    codes = {code for code, _ in scan.exit_codes}
    assert codes == {"0", "1", "130"}


def test_documented_set_keys_are_the_ones_the_command_accepts():
    registry = CommandRegistry()
    register_builtins(registry)
    usage = registry.resolve("set").usage
    for key in ("proxy", "passive", "rate"):
        assert key in usage
        assert key in (DOCS_DIR / "QUICKSTART.md").read_text()


# ── Documented paths and config keys must be real ─────────────────────────────

def test_documented_repository_paths_exist():
    text = README.read_text()
    for rel in re.findall(r"\]\((docs/[A-Za-z_]+\.md|configs/[a-z]+\.yaml|LICENSE|"
                          r"CONTRIBUTING\.md|SECURITY\.md|CODE_OF_CONDUCT\.md)\)", text):
        assert (REPO_ROOT / rel).exists(), f"README links to missing {rel}"


def test_cross_document_links_resolve():
    for doc in ALL_DOCS:
        for rel in re.findall(r"\]\((?!https?://|#)([^)]+)\)", doc.read_text()):
            target = (doc.parent / rel.split("#")[0]).resolve()
            assert target.exists(), f"{doc.name} links to missing {rel}"


def test_documented_config_keys_exist_on_the_model():
    """A YAML profile in the docs must actually load."""
    from spyder.core.config import SpyderConfig

    fields = set(SpyderConfig.model_fields)
    for key in ("passive_mode", "http", "crawl", "plugin_dirs"):
        assert key in fields, f"documented config key '{key}' is not a real field"

    assert "timeout" in type(SpyderConfig().http).model_fields
    assert "max_depth" in type(SpyderConfig().crawl).model_fields


def test_shipped_config_profiles_load():
    from spyder.core.config import SpyderConfig

    for profile in (REPO_ROOT / "configs").glob("*.yaml"):
        SpyderConfig.from_profile(profile)


def test_documented_environment_variables_work(tmp_path, monkeypatch):
    """SPYDER_HOME and the SPYDER_* overrides are promised in the README."""
    from spyder.core.config import load_config

    monkeypatch.setenv("SPYDER_HOME", str(tmp_path / "engagement"))
    monkeypatch.setenv("SPYDER_PASSIVE_MODE", "true")
    cfg = load_config()
    assert cfg.home == (tmp_path / "engagement").resolve()
    assert cfg.passive_mode is True


def test_documented_default_data_directory_layout_is_created(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    from spyder.core.config import load_config

    load_config()
    for documented in ("db", "workspaces", "reports", "logs", "configs", "plugins"):
        assert (tmp_path / documented).is_dir(), f"docs promise {documented}/"


# ── Plugin documentation must match the framework ─────────────────────────────

def test_documented_plugin_contracts_exist():
    import spyder.plugins.framework as fw

    text = (DOCS_DIR / "PLUGIN_DEVELOPMENT.md").read_text()
    for name in re.findall(r"`(\w+Plugin)`", text):
        assert hasattr(fw, name), f"docs reference non-existent contract {name}"


def test_documented_plugin_methods_exist():
    """Each contract's documented method is the one the ABC actually declares."""
    import spyder.plugins.framework as fw

    expected = {
        "AnalyzerPlugin": "analyze",
        "ReconPlugin": "recon",
        "ConnectorPlugin": "run",
        "ReporterPlugin": "render",
        "ReplayPlugin": "on_replay",
        "ReplayAnalyzerPlugin": "analyze_replay",
        "ReplayVisualizationPlugin": "visualize_replay",
        "DashboardWidgetPlugin": "render",
        "VisualizationPlugin": "visualize",
    }
    for contract, method in expected.items():
        assert hasattr(getattr(fw, contract), method), f"{contract}.{method} is documented but absent"


def test_documented_connector_lifecycle_stages_exist():
    from spyder.plugins.framework import ConnectorPlugin

    for stage in ("initialize", "validate", "execute", "parse", "cleanup",
                  "status", "invoke"):
        assert hasattr(ConnectorPlugin, stage), f"documented stage {stage}() is missing"


def test_documented_pipeline_stages_exist():
    from spyder.core.pipeline import PipelineStage

    documented = ["parse", "validate", "permission", "workspace", "execute",
                  "plugins", "result", "database", "render"]
    actual = [s.value for s in PipelineStage]
    assert actual == documented, f"README pipeline order {documented} != {actual}"


def test_documented_cli_facade_imports_work():
    """ARCHITECTURE.md advertises spyder.cli as the stable import surface."""
    from spyder.cli import build_parser as facade_parser
    from spyder.cli import main, render_banner, run_console
    from spyder.cli.progress import err, info, ok, warn

    assert facade_parser is build_parser
    for obj in (main, render_banner, run_console, info, ok, err, warn):
        assert callable(obj)


def test_example_plugin_matches_the_documented_contract():
    """The shipped example must still be a valid plugin."""
    from spyder.plugins.framework import AnalyzerPlugin, PluginRegistry

    registry = PluginRegistry()
    loaded = registry.load_dir(REPO_ROOT / "plugins")
    assert loaded >= 1, "the example plugin no longer loads"
    assert "reflection-review" in registry.analyzers
    assert isinstance(registry.analyzers["reflection-review"], AnalyzerPlugin)


# ── Accuracy of specific claims ───────────────────────────────────────────────

def test_docs_do_not_claim_the_repository_plugins_dir_is_auto_loaded():
    """The v1.0 audit's headline documentation defect — pin it shut.

    Only $SPYDER_HOME/plugins and configured plugin_dirs are scanned. The README
    used to tell users to drop a file in the repository's plugins/ directory,
    where it would never be found.
    """
    from spyder.core.config import load_config

    cfg = load_config()
    assert REPO_ROOT / "plugins" not in cfg.plugin_dirs

    claim = re.compile(r"drop.{0,40}`?plugins/`?\s+directory", re.IGNORECASE | re.DOTALL)
    for doc in (README, DOCS_DIR / "PLUGIN_DEVELOPMENT.md", DOCS_DIR / "INSTALL.md"):
        assert not claim.search(doc.read_text()), (
            f"{doc.name} implies the repo's plugins/ directory is auto-loaded — it is not"
        )


def test_no_placeholder_repository_urls_remain():
    for doc in ALL_DOCS:
        text = doc.read_text()
        for placeholder in ("yourhandle", "YOUR_USERNAME", "OWNER/spyder", "example-org"):
            assert placeholder not in text, f"{doc.name} still contains '{placeholder}'"


def test_documented_python_requirement_matches_packaging():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert 'requires-python = ">=3.12"' in pyproject
    assert "3.12" in README.read_text()
    assert "3.12" in (DOCS_DIR / "INSTALL.md").read_text()


def test_documented_extras_exist_in_packaging():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    for extra in ("pdf", "fast", "dev"):
        assert re.search(rf"^{extra} = \[", pyproject, re.MULTILINE), f"extra '{extra}' is documented but not packaged"


def test_test_count_claims_match_reality():
    """Docs quote a test count; keep it honest or drop the number.

    Collected in a subprocess rather than read off ``request.session`` so the
    check is correct when only a subset of the suite is being run.
    """
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    assert match, f"could not determine the collected test count:\n{proc.stdout[-500:]}"
    collected = int(match.group(1))

    def _counts(text: str) -> list[int]:
        return [int(n) for n in re.findall(r"\*{0,2}(\d{2,4})\*{0,2} (?:tests|passing)", text)]

    claims = []
    for doc in (README, CONTRIBUTING):
        claims += [(doc.name, n) for n in _counts(doc.read_text())]
    # Only the CHANGELOG's Unreleased section is held to the *current* count.
    # Counts inside released sections are point-in-time records of what passed
    # at that release; rewriting them to match today's suite would falsify history.
    unreleased = re.search(r"^## \[Unreleased\](.*?)(?=^## \[)", CHANGELOG.read_text(),
                           re.S | re.M)
    if unreleased:
        claims += [(f"{CHANGELOG.name} [Unreleased]", n) for n in _counts(unreleased.group(1))]
    assert claims, "no test-count claim found — was the wording changed?"
    for name, claimed in claims:
        assert claimed == collected, (
            f"{name} claims {claimed} tests; the suite collects {collected}"
        )
