"""Findings must be auditable: classified, evidenced, and actually produced.

The gap these tests close is that the suite exercised the report *writers* and
the fingerprint *analyser* but never the orchestrator path that turns one into
the other, so a finding-construction error was invisible to 438 passing tests.
"""
from __future__ import annotations

import asyncio

import pytest

from spyder.core.config import SpyderConfig
from spyder.core.models import Finding, Target
from spyder.core.orchestrator import Orchestrator
from spyder.reporting.catalogue import CATALOGUE, INFORMATIONAL, apply_to, classify
from verification.groundtruth.server import ground_truth_server


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SPYDER_HOME", str(tmp_path))
    c = SpyderConfig()
    c.home = tmp_path
    return c


def _recon(cfg, name):
    with ground_truth_server() as base:
        orch = Orchestrator(cfg, name)
        asyncio.run(orch.recon(Target(base_url=base)))
        return orch, orch.wm.get_findings(orch.ws_id)


def _by_key(findings, key):
    return [f for f in findings if (f.get("key") if isinstance(f, dict) else f.key) == key]


def _get(f, field):
    return f.get(field) if isinstance(f, dict) else getattr(f, field)


# --- the reproduced defect: recon() never completed the fingerprint finding ---


def test_recon_produces_a_passive_fingerprint_finding(cfg):
    """Regression for R7-001: recon() raised NameError building this finding."""
    _, findings = _recon(cfg, "fp")
    assert _by_key(findings, "passive-fingerprint"), (
        f"no passive-fingerprint finding; got {[_get(f, 'title') for f in findings]}"
    )


def test_fingerprint_finding_carries_its_evidence_and_confidence(cfg):
    _, findings = _recon(cfg, "fp-evidence")
    f = _by_key(findings, "passive-fingerprint")[0]
    ev = _get(f, "evidence")
    assert ev["technology_entities"], "claim recorded with no supporting evidence"
    for ent in ev["technology_entities"]:
        assert ent.get("evidence"), f"{ent.get('name')} asserted with no evidence source"
    assert _get(f, "confidence") in {"confirmed", "high", "medium", "low", "noise"}
    assert 0 <= _get(f, "confidence_score") <= 100


def test_version_disclosure_raised_only_when_a_version_was_seen(cfg):
    """The ground-truth seed discloses nginx/1.24.0, so this must be raised."""
    _, findings = _recon(cfg, "ver")
    vd = _by_key(findings, "version-disclosure")
    assert vd, "server disclosed nginx/1.24.0 but no version-disclosure finding"
    assert "Nginx" in _get(vd[0], "evidence")["versions"]


def test_version_disclosure_confidence_comes_from_the_versioned_evidence(cfg):
    """Regression for R7-005.

    Confidence was ``max()`` over *every* detected technology, so the finding
    inherited the score of whichever entity happened to rank highest — on the
    ground-truth site, Express at ``confirmed (88)``, which discloses no version
    at all. The claim being made ("nginx/1.24.0 was disclosed") is supported by
    a single header source, i.e. ``high (80)``. A confidence that outruns the
    evidence printed beside it is exactly what makes a report untrustworthy.
    """
    _, findings = _recon(cfg, "ver-conf")
    f = _by_key(findings, "version-disclosure")[0]
    assert _get(f, "confidence") == "high", (
        f"claims {_get(f, 'confidence')} for a single-source passive header"
    )
    assert _get(f, "confidence_score") == 80


def test_no_finding_claims_more_confidence_than_its_evidence(cfg):
    """A passive observation cannot be 'confirmed' — see spyder.validation.fingerprint."""
    _, findings = _recon(cfg, "no-overclaim")
    for f in findings:
        ents = (_get(f, "evidence") or {}).get("technology_entities")
        if not ents:
            continue
        if all(len({e["source"] for e in ent["evidence"]}) < 2 for ent in ents):
            assert _get(f, "confidence") != "confirmed", (
                f"{_get(f, 'key')}: confirmed on single-source passive evidence"
            )


# --- classification invariants ---


def test_every_finding_asserting_a_weakness_is_classified(cfg):
    """A weakness with no CWE/OWASP sends an analyst to no control at all."""
    _, findings = _recon(cfg, "classified")
    for f in findings:
        key = _get(f, "key")
        if not key or key in INFORMATIONAL:
            continue
        assert _get(f, "cwe"), f"{key}: asserts a weakness with no CWE"
        assert _get(f, "owasp"), f"{key}: asserts a weakness with no OWASP category"
        assert _get(f, "references"), f"{key}: no reference to read further"
        assert _get(f, "remediation"), f"{key}: no remediation"


def test_informational_findings_claim_no_weakness(cfg):
    """Mapping an inventory to a CWE would invent a weakness nobody observed."""
    _, findings = _recon(cfg, "informational")
    for f in findings:
        if _get(f, "key") in INFORMATIONAL:
            assert not _get(f, "cwe"), f"{_get(f, 'key')}: informational, yet carries a CWE"
            assert not _get(f, "owasp")


def test_catalogue_keys_are_disjoint_from_informational_keys():
    assert not (set(CATALOGUE) & INFORMATIONAL)


def test_apply_to_populates_from_the_catalogue():
    kw = apply_to("version-disclosure", title="t", endpoint="http://x")
    assert kw["cwe"] == ["CWE-200"]
    assert kw["key"] == "version-disclosure"
    assert kw["remediation"]
    assert Finding(**kw).owasp == ["A05:2021-Security Misconfiguration"]


def test_explicit_arguments_beat_the_catalogue():
    kw = apply_to("version-disclosure", title="t", cwe=["CWE-1"])
    assert kw["cwe"] == ["CWE-1"]


def test_unknown_key_classifies_as_nothing_rather_than_guessing():
    assert classify("no-such-finding") is None
    kw = apply_to("no-such-finding", title="t")
    assert kw["key"] == "no-such-finding"
    assert "cwe" not in kw


def test_every_catalogue_entry_is_complete_and_referenced():
    for key, entry in CATALOGUE.items():
        assert entry.cwe, f"{key}: no CWE"
        assert entry.owasp, f"{key}: no OWASP category"
        assert entry.remediation, f"{key}: no remediation"
        # Every asserted CWE must be reachable from the references.
        for cwe in entry.cwe:
            num = cwe.split("-")[1]
            assert any(f"/{num}.html" in r for r in entry.references), (
                f"{key}: {cwe} asserted with no link to its definition"
            )
