"""Tests for recon-pipeline connectors and discovery summarization."""
from __future__ import annotations

import pytest

from spyder.analysis.discovery import summarize_discovery
from spyder.connectors.base import ConnectorError
from spyder.connectors.recon import (
    RECON_CONNECTORS,
    FfufConnector,
    SubfinderConnector,
    _host,
    _norm_subdomain,
    _norm_url,
)
from spyder.core.models import Finding, Severity


def test_host_extraction():
    assert _host("https://app.example.com:8443/path") == "app.example.com"
    assert _host("example.com") == "example.com"
    assert _host("http://user@host.example.com/x") == "host.example.com"


def test_norm_subdomain():
    assert _norm_subdomain("API.Example.COM") == "api.example.com"
    assert _norm_subdomain("https://sub.example.com/path") == "sub.example.com"
    assert _norm_subdomain("not a domain") is None
    assert _norm_subdomain("localhost") is None  # no dot


def test_norm_url():
    assert _norm_url("example.com/x") == "http://example.com/x"
    assert _norm_url("https://example.com/y") == "https://example.com/y"
    assert _norm_url("# comment") is None
    assert _norm_url("") is None


def test_norm_url_rejects_fabricated_noise():
    # Regression: arbitrary tool prose/error text must never become a "URL".
    # Previously any non-empty line was blindly turned into http://<line>.
    noise = [
        "The httpx command line client could not run because deps missing.",
        "Make sure you've installed everything with: pip install 'httpx[cli]'",
        "random noise text here",
        "error: something went wrong",
    ]
    for line in noise:
        assert _norm_url(line) is None, line


def test_norm_url_accepts_real_targets_with_suffix_columns():
    # httpx appends [status] [title] columns; the URL is the first token.
    assert _norm_url("http://127.0.0.1:8099 [200] [Home]") == "http://127.0.0.1:8099"
    assert _norm_url("https://sub.example.com/a?x=1") == "https://sub.example.com/a?x=1"
    assert _norm_url("http://[::1]:8080/x") == "http://[::1]:8080/x"


def test_httpx_shim_detection(tmp_path):
    # Regression: SPYDER's own httpx dependency ships an 'httpx' console script
    # that shadows ProjectDiscovery httpx. The Python shim must be rejected so we
    # never fabricate findings from its output; a native binary must be accepted.
    from spyder.connectors.recon import _is_python_httpx_shim

    shim = tmp_path / "httpx"
    shim.write_text("#!/usr/bin/python3\nimport httpx\n")
    assert _is_python_httpx_shim(str(shim)) is True

    native = tmp_path / "httpx_native"
    native.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    assert _is_python_httpx_shim(str(native)) is False

    assert _is_python_httpx_shim(str(tmp_path / "missing")) is False


def test_recon_connectors_metadata():
    names = {c.name for c in RECON_CONNECTORS}
    assert {"subfinder", "amass", "assetfinder", "httpx", "katana", "gau", "waybackurls", "ffuf"} <= names
    # subdomain tools vs url tools
    sub = SubfinderConnector()
    assert sub.result_kind == "subdomains"
    assert sub.binary == "subfinder"


def test_summary_finding_shape():
    finding = SubfinderConnector()._summary("https://example.com", ["a.example.com", "b.example.com"])[0]
    assert finding.severity is Severity.INFO
    assert finding.source == "SPYDER:subfinder"
    assert finding.evidence["subdomains"] == ["a.example.com", "b.example.com"]
    assert finding.evidence["count"] == 2


async def test_ffuf_requires_wordlist():
    with pytest.raises(ConnectorError):
        await FfufConnector().run("http://example.com", {})


def test_available_does_not_crash_without_binary():
    # Should return a bool even when the tool is not installed.
    assert isinstance(SubfinderConnector().available(), bool)


def test_summarize_discovery_dedup_and_attribution():
    findings = [
        Finding(title="subfinder", severity=Severity.INFO, source="SPYDER:subfinder",
                evidence={"subdomains": ["a.example.com", "b.example.com"]}),
        Finding(title="assetfinder", severity=Severity.INFO, source="SPYDER:assetfinder",
                evidence={"subdomains": ["b.example.com", "c.example.com"]}),
        Finding(title="gau", severity=Severity.INFO, source="SPYDER:gau",
                evidence={"urls": ["https://example.com/1", "https://example.com/2"]}),
        Finding(title="noise", severity=Severity.INFO, source="SPYDER", evidence={}),
    ]
    s = summarize_discovery(findings)
    assert s.subdomains == {"a.example.com", "b.example.com", "c.example.com"}  # deduped
    assert len(s.urls) == 2
    assert s.by_tool["subfinder"] == 2
    assert s.by_tool["assetfinder"] == 2
    assert s.total == 5
