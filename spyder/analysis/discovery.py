"""Discovery summarization — aggregate recon-tool output into a unified view.

Reads the evidence of recon-pipeline findings (subfinder/amass/gau/...) and
collapses them into a single deduplicated inventory of subdomains and URLs with
per-tool attribution, for the dashboard's recon panels and reports.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..core.models import Finding


@dataclass
class DiscoverySummary:
    subdomains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    by_tool: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.subdomains) + len(self.urls)

    @property
    def empty(self) -> bool:
        return self.total == 0


def _tool_of(finding: Finding) -> str:
    # source looks like "SPYDER:subfinder"
    return finding.source.split(":")[-1] if finding.source else "unknown"


def summarize_discovery(findings: list[Finding]) -> DiscoverySummary:
    summary = DiscoverySummary()
    by_tool: Counter[str] = Counter()
    for f in findings:
        ev = f.evidence or {}
        subs = ev.get("subdomains")
        urls = ev.get("urls")
        if not (subs or urls):
            continue
        tool = _tool_of(f)
        if subs:
            summary.subdomains.update(subs)
            by_tool[tool] += len(subs)
        if urls:
            summary.urls.update(urls)
            by_tool[tool] += len(urls)
    summary.by_tool = dict(by_tool)
    return summary
