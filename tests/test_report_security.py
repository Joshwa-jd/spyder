"""Security regression: HTML reports must escape attacker-influenced fields.

Finding titles, endpoints, descriptions, remediation, source, and the workspace
label can all be steered by a target's responses or a tool's output. If the HTML
report renders them unescaped, opening the report executes attacker JavaScript in
the analyst's browser (stored XSS).

The regression this guards: the templates end in ``.j2``, so
``select_autoescape(["html", "xml"])`` silently left autoescaping OFF. The engine
now enables autoescaping for ``*.html.j2`` (and the macro library was renamed to
``_macros.html.j2`` so macro-rendered fields are escaped too), while our own SVG
stays raw via ``| safe``.
"""
from __future__ import annotations

from pathlib import Path

from spyder.core.models import Finding, Severity
from spyder.reporting.engine import ReportEngine

_PAYLOADS = {
    "title": "T<script>alert('t')</script>",
    "endpoint": "https://x/<img src=q onerror=alert('e')>",
    "description": "D<svg/onload=alert('d')>",
    "remediation": "R<iframe src=javascript:alert('r')>",
}


def _html(tmp_path: Path) -> str:
    f = Finding(
        title=_PAYLOADS["title"],
        severity=Severity.HIGH,
        endpoint=_PAYLOADS["endpoint"],
        description=_PAYLOADS["description"],
        remediation=_PAYLOADS["remediation"],
        source="SPYDER:t",
    )
    path = ReportEngine().export("html", "ws", "target", [f], tmp_path)
    return path.read_text()


def test_html_report_escapes_all_attacker_fields(tmp_path):
    html = _html(tmp_path)
    # No raw executable markup from any field survives.
    for bad in ("<script>alert", "onerror=alert('e')>", "<svg/onload=alert",
                "<iframe src=javascript"):
        assert bad not in html, f"unescaped payload in HTML report: {bad!r}"
    # And the text is present in escaped form (so it's rendered, just inert).
    assert "&lt;script&gt;alert" in html


def test_html_report_keeps_trusted_svg_raw(tmp_path):
    # Our own logo / diagram SVG is injected with | safe and must NOT be escaped.
    html = _html(tmp_path)
    assert "<svg" in html and "&lt;svg" not in html.split("finding-title", 1)[0]


def test_markdown_report_is_not_html_escaped(tmp_path):
    f = Finding(title="A & B <c>", severity=Severity.LOW, endpoint="https://x",
                description="x & y", source="SPYDER:t")
    md = ReportEngine().export("md", "ws", "t", [f], tmp_path).read_text()
    assert "&amp;" not in md and "&lt;" not in md, "markdown must not be HTML-escaped"


def test_json_report_round_trips_special_chars(tmp_path):
    import json
    f = Finding(title=_PAYLOADS["title"], severity=Severity.HIGH,
                endpoint=_PAYLOADS["endpoint"], source="SPYDER:t")
    data = json.loads(ReportEngine().export("json", "ws", "t", [f], tmp_path).read_text())
    assert data["total"] == 1
    assert data["findings"][0]["title"] == _PAYLOADS["title"]
