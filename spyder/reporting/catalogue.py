"""Classification catalogue: CWE / OWASP / reference mappings for SPYDER findings.

Mappings live here as reviewable data rather than as literals scattered across
the call sites that happen to raise a finding. Two reasons:

  * **They are checkable.** Every entry below was read off the authoritative
    source — MITRE for the CWE title, the OWASP Top 10 2021 category page for
    the category title and its mapped CWE list — rather than recalled. A wrong
    mapping is worse than no mapping: it sends an analyst to the wrong control.
  * **They are shared.** A finding raised by the orchestrator, a connector, or a
    plugin classifies identically, so a report never explains the same weakness
    two different ways.

A finding that asserts a *weakness* must carry a classification. A purely
informational observation — an inventory of technologies, a tool-status note —
carries none, and that is deliberate: mapping an inventory to a CWE would be
inventing a weakness nobody observed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_CWE = "https://cwe.mitre.org/data/definitions/{}.html"
_OWASP_2021 = "https://owasp.org/Top10/2021/{}/"


@dataclass(frozen=True)
class Classification:
    """How one class of finding maps onto the public weakness taxonomies."""

    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    remediation: str
    references: tuple[str, ...]


#: Keyed by a stable finding key. Titles are quoted exactly as the authorities
#: publish them, so a reader can diff this table against the source.
CATALOGUE: dict[str, Classification] = {
    # Credentials embedded in code the server hands to every visitor.
    # CWE-540 is the precise weakness (source code, not comments — CWE-615 is
    # the comments variant and does not apply to a served bundle). CWE-798 is
    # what makes it exploitable, and it is CWE-798 that OWASP maps to A07.
    "secrets-in-javascript": Classification(
        cwe=("CWE-540", "CWE-798"),
        owasp=("A07:2021-Identification and Authentication Failures",),
        remediation=(
            "Move secrets server-side; never ship credentials in client-delivered "
            "bundles. Rotate every exposed value — publication is disclosure, so "
            "removing the code does not undo it."
        ),
        references=(
            _CWE.format(540),
            _CWE.format(798),
            _OWASP_2021.format("A07_2021-Identification_and_Authentication_Failures"),
        ),
    ),
    # Input observed reflected into a response. SPYDER reports the reflection,
    # not a proven XSS — the severity and wording stay at "review this".
    "reflected-input": Classification(
        cwe=("CWE-79",),
        owasp=("A03:2021-Injection",),
        remediation=(
            "Apply context-aware output encoding at every sink and validate input "
            "against an allowlist."
        ),
        references=(_CWE.format(79), _OWASP_2021.format("A03_2021-Injection")),
    ),
    # A server volunteering exact product versions widens an attacker's search.
    # Claimed only when a version was actually disclosed, never for a bare
    # technology inventory.
    "version-disclosure": Classification(
        cwe=("CWE-200",),
        owasp=("A05:2021-Security Misconfiguration",),
        remediation=(
            "Suppress product and version banners in responses (server tokens, "
            "X-Powered-By, framework generator tags)."
        ),
        references=(_CWE.format(200), _OWASP_2021.format("A05_2021-Security_Misconfiguration")),
    ),
}

#: Finding keys that are purely observational. Listing them explicitly means a
#: missing classification is a deliberate decision on the record, not an
#: oversight the invariant test has to guess about.
INFORMATIONAL: frozenset[str] = frozenset({
    "passive-fingerprint",
    "connector-status",
})


def classify(key: str) -> Classification | None:
    """The classification for a finding key, or ``None`` if it asserts no weakness."""
    return CATALOGUE.get(key)


def apply_to(key: str, **kw: Any) -> dict[str, Any]:
    """Merge a catalogue entry into ``Finding`` keyword arguments.

    Explicit keyword arguments win, so a caller with better information than the
    table can always override it.

    ``Any`` rather than ``object``: the values are genuinely heterogeneous
    (strings, enums, lists, evidence dicts) and are splatted into ``Finding``,
    whose own field types are the real check. Typing them as ``object`` only
    moves the error to every call site without catching anything.
    """
    entry = classify(key)
    if entry is not None:
        kw.setdefault("cwe", list(entry.cwe))
        kw.setdefault("owasp", list(entry.owasp))
        kw.setdefault("references", list(entry.references))
        if entry.remediation:
            kw.setdefault("remediation", entry.remediation)
    kw.setdefault("key", key)
    return kw
