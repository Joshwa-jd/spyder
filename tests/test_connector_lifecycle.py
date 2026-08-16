"""Regression tests for the connector six-stage lifecycle.

Guards the uniform ``initialize → validate → execute → parse → cleanup`` +
``status`` contract every connector must expose, and the ``invoke`` orchestration
that the orchestrator drives. See ``spyder.plugins.framework.ConnectorPlugin``.
"""
from __future__ import annotations

import pytest

from spyder.connectors.base import ConnectorError as BaseConnectorError
from spyder.connectors.base import ExternalToolConnector
from spyder.connectors.burp import BurpConnector
from spyder.connectors.nuclei import NucleiConnector
from spyder.connectors.recon import RECON_CONNECTORS
from spyder.connectors.sqlmap import SqlmapConnector
from spyder.core.models import Finding
from spyder.plugins.framework import (
    ConnectorError,
    ConnectorPlugin,
    ConnectorValidation,
)

_LIFECYCLE = ("initialize", "validate", "execute", "parse", "cleanup", "status")
_ALL_CONNECTORS = [NucleiConnector, SqlmapConnector, BurpConnector, *RECON_CONNECTORS]


@pytest.mark.parametrize("cls", _ALL_CONNECTORS)
def test_every_connector_exposes_the_full_lifecycle(cls):
    c = cls()
    for method in (*_LIFECYCLE, "invoke", "run", "available"):
        assert callable(getattr(c, method, None)), f"{cls.__name__} missing {method}()"


def test_connector_error_is_a_single_shared_class():
    # No duplicate class: the framework definition and the base re-export are one.
    assert ConnectorError is BaseConnectorError
    assert issubclass(ConnectorError, RuntimeError)


@pytest.mark.parametrize("cls", _ALL_CONNECTORS)
def test_status_reports_required_keys(cls):
    st = cls().status()
    for key in ("name", "version", "type", "available", "initialized", "last_ok"):
        assert key in st
    assert st["type"] == "connector"
    if isinstance(cls(), ExternalToolConnector):
        assert "binary" in st and "path" in st


def test_base_validate_requires_target():
    v = BurpConnector().validate("", {})
    assert not v.ok
    assert "no target provided" in v.errors


def test_external_tool_validate_flags_missing_binary():
    class _Ghost(ExternalToolConnector):
        name = "ghost"
        binary = "__definitely_not_a_real_binary__"

        async def run(self, target, options):  # pragma: no cover - never reached
            return []

    v = _Ghost().validate("http://ex.com", {})
    assert not v.ok
    assert any("not found on PATH" in e for e in v.errors)


def test_parse_normalizes_a_findings_list():
    findings = NucleiConnector().parse([Finding(title="a"), "junk", Finding(title="b")])
    assert [f.title for f in findings] == ["a", "b"]
    assert NucleiConnector().parse("not a list") == []


async def test_invoke_runs_stages_in_order():
    calls: list[str] = []

    class _Recorder(ConnectorPlugin):
        name = "recorder"

        def on_initialize(self):
            calls.append("initialize")

        def validate(self, target, options=None):
            calls.append("validate")
            return ConnectorValidation.success()

        async def run(self, target, options):
            calls.append("run")
            return [Finding(title="ok")]

        def on_cleanup(self):
            calls.append("cleanup")

    conn = _Recorder()
    result = await conn.invoke("http://ex.com", {"k": "v"})
    assert [f.title for f in result] == ["ok"]
    assert calls == ["initialize", "validate", "run", "cleanup"]
    assert conn.status()["initialized"] is True
    assert conn.status()["last_ok"] is True


async def test_invoke_raises_and_still_cleans_up_on_validation_failure():
    cleaned: list[bool] = []

    class _BadTarget(ConnectorPlugin):
        name = "badtarget"

        def on_cleanup(self):
            cleaned.append(True)

        async def run(self, target, options):  # pragma: no cover - never reached
            return []

    with pytest.raises(ConnectorError):
        await _BadTarget().invoke("", {})  # empty target fails base validate()
    assert cleaned == [True]  # cleanup ran despite the failure


async def test_invoke_matches_direct_run_for_a_valid_connector():
    """The lifecycle wrapper must not change results for a normal connector."""

    class _Two(ConnectorPlugin):
        name = "two"

        async def run(self, target, options):
            return [Finding(title="x"), Finding(title="y")]

    conn = _Two()
    via_invoke = await conn.invoke("http://ex.com", {})
    via_run = await conn.run("http://ex.com", {})
    assert [f.title for f in via_invoke] == [f.title for f in via_run] == ["x", "y"]
