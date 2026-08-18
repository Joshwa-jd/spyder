"""Deterministic SVG rendering for intelligence graphs (embeddable in reports).

Given a :class:`~spyder.analysis.graph.Graph`, this produces a self-contained,
byte-reproducible SVG string: a layered tree with confidence-heat-mapped nodes
and orthogonal containment edges. All colour comes from the centralized
``ui.theme`` palette so report diagrams match the cyberpunk SOC theme.

Determinism: layout is structural (see :func:`layered_layout`), coordinates are
integers, and nodes/edges emit in sorted order — the same graph always renders to
the identical SVG, which is what makes the diagrams trustworthy and testable.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from ..analysis.graph import Graph, NodeKind, layered_layout
from ..ui.theme import CONFIDENCE_COLORS, HTML_PALETTE

# Fixed geometry — integers keep output byte-stable.
_COL_W = 210
_ROW_H = 34
_NODE_W = 188
_NODE_H = 24
_MARGIN = 16

# Per-kind stroke accents (deterministic, theme-derived).
_KIND_STROKE: dict[str, str] = {
    NodeKind.HOST.value: HTML_PALETTE["neon_red"],
    NodeKind.CLUSTER.value: HTML_PALETTE["ember"],
    NodeKind.GROUP.value: HTML_PALETTE["muted"],
    NodeKind.ENDPOINT.value: HTML_PALETTE["fg"],
    NodeKind.TECH.value: HTML_PALETTE["success"],
    NodeKind.ROUTE.value: HTML_PALETTE["warning"],
}

_GLYPH: dict[str, str] = {
    NodeKind.HOST.value: "◉",
    NodeKind.CLUSTER.value: "▣",
    NodeKind.GROUP.value: "▸",
    NodeKind.ENDPOINT.value: "●",
    NodeKind.TECH.value: "⚙",
    NodeKind.ROUTE.value: "↳",
}


def _level_color(level: str) -> str:
    return CONFIDENCE_COLORS.get(level, HTML_PALETTE["subtle"])


def _truncate(label: str, limit: int = 26) -> str:
    return label if len(label) <= limit else label[: limit - 1] + "…"


def render_svg(graph: Graph, *, max_rows: int = 60) -> str:
    """Render ``graph`` as a deterministic, embeddable SVG document string."""
    layout = layered_layout(graph)
    palette = HTML_PALETTE
    if not layout.placed:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="320" height="60" '
            f'role="img" aria-label="empty graph">'
            f'<rect width="320" height="60" fill="{palette["panel_bg"]}"/>'
            f'<text x="16" y="34" fill="{palette["muted"]}" '
            f'font-family="monospace" font-size="13">no intelligence to map yet</text>'
            f"</svg>"
        )

    placed = layout.placed[:max_rows]
    pos = {p.node.id: p for p in placed}
    width = _MARGIN * 2 + layout.width * _COL_W
    height = _MARGIN * 2 + len(placed) * _ROW_H

    def nx(depth: int) -> int:
        return _MARGIN + depth * _COL_W

    def ny(order: int) -> int:
        return _MARGIN + order * _ROW_H

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{escape(graph.title)} intelligence graph">',
        f'<rect width="{width}" height="{height}" fill="{palette["panel_bg"]}"/>',
    ]

    # Edges first (so nodes paint over them). Orthogonal parent→child connectors.
    for edge in layout.edges:
        sp, tp = pos.get(edge.source), pos.get(edge.target)
        if not sp or not tp:
            continue
        x1 = nx(sp.depth) + _NODE_W
        y1 = ny(sp.order) + _NODE_H // 2
        x2 = nx(tp.depth)
        y2 = ny(tp.order) + _NODE_H // 2
        midx = (x1 + x2) // 2
        path = f"M{x1},{y1} H{midx} V{y2} H{x2}"
        parts.append(
            f'<path d="{path}" fill="none" stroke="{palette["rule"]}" '
            f'stroke-width="1.2" opacity="0.7"/>'
        )

    # Nodes.
    for p in placed:
        n = p.node
        x, y = nx(p.depth), ny(p.order)
        stroke = _KIND_STROKE.get(n.kind.value, palette["fg"])
        heat = _level_color(n.level) if n.level else palette["subtle"]
        glyph = _GLYPH.get(n.kind.value, "•")
        label = _truncate(n.label)
        wsuffix = f" ×{n.weight}" if n.kind is NodeKind.CLUSTER and n.weight > 1 else ""
        parts.append(
            f'<g>'
            f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="4" '
            f'fill="{palette["bg"]}" stroke="{stroke}" stroke-width="1.4"/>'
            # confidence heat bar on the left edge
            f'<rect x="{x}" y="{y}" width="4" height="{_NODE_H}" rx="2" fill="{heat}"/>'
            f'<text x="{x + 10}" y="{y + 16}" fill="{heat}" '
            f'font-family="monospace" font-size="12">{escape(glyph)}</text>'
            f'<text x="{x + 26}" y="{y + 16}" fill="{palette["fg"]}" '
            f'font-family="monospace" font-size="12">{escape(label + wsuffix)}</text>'
            f"</g>"
        )

    if layout.height > len(placed):
        hidden = layout.height - len(placed)
        parts.append(
            f'<text x="{_MARGIN}" y="{height - 4}" fill="{palette["muted"]}" '
            f'font-family="monospace" font-size="11">+{hidden} more nodes…</text>'
        )

    parts.append("</svg>")
    return "".join(parts)
