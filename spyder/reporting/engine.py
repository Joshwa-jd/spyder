"""Reporting engine: renders findings to HTML, JSON, and Markdown.

PDF is optional (requires weasyprint). Reports lead with a risk summary and
include evidence, CWE/OWASP mappings, and remediation guidance.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from ..core.models import Finding, Severity
from ..ui.theme import HTML_PALETTE
from ..utils.logging import get_logger
from ..utils.paths import safe_slug

if TYPE_CHECKING:
    from ..analysis.graph import Graph

log = get_logger("reporting")

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_LOGO_SVG = Path(__file__).parent.parent / "ui" / "assets" / "spyder_logo.svg"


def _load_logo() -> str:
    try:
        return _LOGO_SVG.read_text(encoding="utf-8")
    except OSError:
        return ""


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Severity}


def _autoescape_for(template_name: str | None) -> bool:
    """Enable HTML autoescaping for HTML/XML templates — including the ``.j2``
    variants.

    ``jinja2.select_autoescape(["html", "xml"])`` keys off the file extension, so
    ``report.html.j2`` (ending in ``.j2``) slips through with autoescaping OFF —
    which let attacker-influenced finding fields (titles, endpoints reflected from
    a target, tool output) inject raw HTML/JS into the report, i.e. stored XSS in
    the analyst's browser. We strip a trailing ``.j2`` before matching so
    ``report.html.j2`` is escaped while ``report.md.j2`` (Markdown, must not be
    HTML-escaped) is not. Raw SVG that we generate ourselves is opted back in with
    ``| safe`` in the template.
    """
    if not template_name:
        return False
    name = template_name[:-3] if template_name.endswith(".j2") else template_name
    return name.endswith((".html", ".htm", ".xml"))


class ReportEngine:
    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(_TEMPLATE_DIR),
            autoescape=_autoescape_for,
        )

    def _context(
        self,
        workspace: str,
        target: str,
        findings: list[Finding],
        diagrams: list[dict] | None = None,
    ) -> dict:
        ordered = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
        return {
            "workspace": workspace,
            "target": target,
            "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "findings": ordered,
            "counts": _severity_counts(findings),
            "total": len(findings),
            "logo_svg": _load_logo(),
            "palette": HTML_PALETTE,
            "diagrams": diagrams or [],
        }

    @staticmethod
    def diagrams_from_graphs(graphs: list[Graph]) -> list[dict]:
        """Render intelligence graphs to embeddable ``{title, svg}`` dicts.

        Deterministic: each graph renders to byte-stable SVG via
        :func:`spyder.reporting.graphsvg.render_svg`.
        """
        from .graphsvg import render_svg
        out: list[dict] = []
        for g in graphs:
            if g is None or g.empty:
                continue
            out.append({"title": g.title.replace("-", " ").title(), "svg": render_svg(g)})
        return out

    def render_json(self, workspace: str, target: str, findings: list[Finding]) -> str:
        ctx = self._context(workspace, target, findings)
        ctx.pop("logo_svg", None)
        ctx.pop("palette", None)
        ctx["findings"] = [f.model_dump(mode="json") for f in ctx["findings"]]
        return json.dumps(ctx, indent=2)

    def render_markdown(self, workspace: str, target: str, findings: list[Finding]) -> str:
        return self.env.get_template("report.md.j2").render(**self._context(workspace, target, findings))

    def render_html(
        self,
        workspace: str,
        target: str,
        findings: list[Finding],
        diagrams: list[dict] | None = None,
    ) -> str:
        return self.env.get_template("report.html.j2").render(
            **self._context(workspace, target, findings, diagrams)
        )

    def render_pdf(self, workspace: str, target: str, findings: list[Finding], out: Path) -> Path:
        try:
            from weasyprint import HTML  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("PDF export requires 'weasyprint' (pip install spyder-recon[pdf])") from exc
        html = self.render_html(workspace, target, findings)
        HTML(string=html).write_pdf(str(out))
        return out

    def export(
        self, fmt: str, workspace: str, target: str, findings: list[Finding], out_dir: Path
    ) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        # Sanitize the workspace label: it is operator-supplied and must not be
        # able to steer the report outside out_dir (path traversal).
        base = out_dir / f"{safe_slug(workspace)}-{stamp}"
        if fmt == "json":
            path = base.with_suffix(".json")
            path.write_text(self.render_json(workspace, target, findings), encoding="utf-8")
        elif fmt in ("md", "markdown"):
            path = base.with_suffix(".md")
            path.write_text(self.render_markdown(workspace, target, findings), encoding="utf-8")
        elif fmt == "html":
            path = base.with_suffix(".html")
            path.write_text(self.render_html(workspace, target, findings), encoding="utf-8")
        elif fmt == "pdf":
            path = self.render_pdf(workspace, target, findings, base.with_suffix(".pdf"))
        else:
            raise ValueError(f"Unknown report format: {fmt}")
        log.info("report written: %s", path)
        return path
