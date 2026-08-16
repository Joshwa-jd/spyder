"""Round 7: a report must carry everything needed to audit a claim.

``tests/test_report_security.py`` already covers escaping and injection. This
file covers *completeness* — that each renderer actually surfaces the fields a
reader needs to judge a finding — and encoding robustness.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from spyder.core.models import Finding, Severity
from spyder.reporting.catalogue import apply_to
from spyder.reporting.engine import ReportEngine

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def finding():
    return Finding(
        **apply_to(
            "version-disclosure",
            title="Product versions disclosed",
            severity=Severity.LOW,
            endpoint="http://target.example/",
            description="The server volunteered exact product versions.",
            evidence={"versions": {"Nginx": "1.24.0"}},
            confidence="high",
            confidence_score=80,
            source="SPYDER",
        )
    )


@pytest.fixture
def engine():
    return ReportEngine()


# --- every renderer surfaces every auditable field ---

#: (label a reader would look for, value that must appear)
_REQUIRED = [
    ("severity", "low"),
    ("location", "http://target.example/"),
    ("source", "SPYDER"),
    ("cwe", "CWE-200"),
    ("owasp", "A05:2021"),
    ("remediation", "Suppress product and version banners"),
    ("evidence", "1.24.0"),
    # "high" alone would match the severity table, so look for the label.
    ("confidence", "confidence"),
    ("reference", "cwe.mitre.org/data/definitions/200.html"),
]


@pytest.mark.parametrize("label,value", _REQUIRED)
def test_markdown_report_carries_every_auditable_field(engine, finding, label, value):
    md = engine.render_markdown("ws", "http://target.example", [finding])
    assert value.lower() in md.lower(), f"markdown report omits {label}"


@pytest.mark.parametrize("label,value", _REQUIRED)
def test_html_report_carries_every_auditable_field(engine, finding, label, value):
    html = engine.render_html("ws", "http://target.example", [finding])
    assert value.lower() in html.lower(), f"HTML report omits {label}"


@pytest.mark.parametrize("render", ["render_markdown", "render_html"])
def test_confidence_is_reported_as_a_level_and_a_score(engine, finding, render):
    """A bare "high" is ambiguous next to a severity column; both must be shown."""
    text = getattr(engine, render)("ws", "http://target.example", [finding]).lower()
    i = text.index("confidence")
    window = text[i : i + 200]
    assert "high" in window, f"{render}: confidence label with no level"
    assert "80" in window, f"{render}: confidence label with no score"


def test_json_report_carries_every_auditable_field(engine, finding):
    doc = json.loads(engine.render_json("ws", "http://target.example", [finding]))
    f = doc["findings"][0]
    for field in (
        "title", "severity", "endpoint", "description", "evidence",
        "cwe", "owasp", "remediation", "references", "confidence",
        "confidence_score", "source", "key",
    ):
        assert field in f, f"JSON report omits {field}"
    assert f["references"], "JSON report has an empty references list"
    assert f["confidence"] == "high"


def test_references_are_absolute_urls(engine, finding):
    doc = json.loads(engine.render_json("ws", "t", [finding]))
    for ref in doc["findings"][0]["references"]:
        assert ref.startswith("https://"), f"non-absolute reference: {ref}"


# --- empty reports ---


@pytest.mark.parametrize("fmt", ["json", "md", "html"])
def test_empty_report_renders_without_claiming_anything(engine, fmt, tmp_path):
    path = engine.export(fmt, "empty-ws", "http://target.example", [], tmp_path)
    text = path.read_text(encoding="utf-8")
    assert text.strip(), "empty report is a zero-length file"
    if fmt == "json":
        doc = json.loads(text)
        assert doc["total"] == 0
        assert doc["findings"] == []
        assert all(v == 0 for v in doc["counts"].values())
    else:
        assert "no findings" in text.lower(), "empty report does not say it found nothing"


# --- unicode ---


_UNICODE_TITLE = "Unicode: 日本語 café — ✓ Ω 🕷"


@pytest.mark.parametrize("fmt", ["json", "md", "html"])
def test_unicode_survives_the_round_trip(engine, fmt, tmp_path):
    f = Finding(title=_UNICODE_TITLE, severity=Severity.INFO, endpoint="http://x/日本")
    path = engine.export(fmt, "ws", "http://x", [f], tmp_path)
    text = path.read_text(encoding="utf-8")
    if fmt == "json":
        # json.dumps escapes non-ASCII by default; decode before comparing.
        assert json.loads(text)["findings"][0]["title"] == _UNICODE_TITLE
    else:
        assert "日本語" in text and "🕷" in text


def test_reports_are_utf8_regardless_of_the_ambient_locale(tmp_path):
    """Regression for R7-003.

    ``Path.write_text`` with no ``encoding`` writes at
    ``locale.getpreferredencoding()``. The HTML template declares
    ``<meta charset="utf-8">``, so on any non-UTF-8 locale SPYDER wrote a file
    whose bytes contradicted its own declaration — and the Markdown and HTML
    writers raised ``UnicodeEncodeError`` outright, defeated by the em dash in
    their own footers.

    PEP 538 coerces C/POSIX to UTF-8, so this is provoked the only way it can be
    provoked on Linux: by turning that coercion off.
    """
    # The script goes to a file, not to -c: under LC_ALL=C the interpreter
    # cannot even decode a non-ASCII command line, which would fail the test
    # for a reason that has nothing to do with the defect.
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from pathlib import Path
        from spyder.core.models import Finding, Severity
        from spyder.reporting.engine import ReportEngine
        f = Finding(title={_UNICODE_TITLE!r}, severity=Severity.INFO)
        e = ReportEngine()
        for fmt in ("json", "md", "html"):
            p = e.export(fmt, "ws", "http://x", [f], Path({str(tmp_path)!r}))
            p.read_bytes().decode("utf-8")   # must be UTF-8 on disk
        print("OK")
    """)
    script_file = tmp_path / "locale_probe.py"
    script_file.write_text(script, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(script_file)],
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONCOERCECLOCALE": "0",  # defeat PEP 538
            "PYTHONUTF8": "0",           # defeat PEP 540
        },
    )
    assert proc.returncode == 0, f"report export failed under a C locale:\n{proc.stderr[-1500:]}"
    assert "OK" in proc.stdout
