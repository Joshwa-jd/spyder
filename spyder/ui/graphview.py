"""Terminal rendering for deterministic intelligence graphs.

Turns a :class:`~spyder.analysis.graph.Graph` into a Rich ``Tree`` (for the
dashboard's attack-surface / cluster panels) with confidence-heat-mapped labels
and per-kind glyphs. The graph itself is already deterministically ordered, so
the rendered tree is reproducible too.

All colour comes from ``spyder.ui.theme``.
"""
from __future__ import annotations

from rich.table import Table
from rich.tree import Tree

from ..analysis.graph import Graph, Node, NodeKind
from .theme import DIM_GREY, MUTED, NEON_RED, OFF_WHITE, confidence_color

_KIND_GLYPH: dict[str, str] = {
    NodeKind.HOST.value: "◉",
    NodeKind.CLUSTER.value: "▣",
    NodeKind.GROUP.value: "▸",
    NodeKind.ENDPOINT.value: "●",
    NodeKind.TECH.value: "⚙",
    NodeKind.ROUTE.value: "↳",
}


def _node_markup(node: Node) -> str:
    glyph = _KIND_GLYPH.get(node.kind.value, "•")
    color = confidence_color(node.level) if node.level else DIM_GREY
    label = f"[{color}]{glyph}[/] [{OFF_WHITE}]{node.label}[/]"
    if node.kind is NodeKind.CLUSTER and node.weight:
        label += f" [{DIM_GREY}]×{node.weight}[/]"
    if node.kind in (NodeKind.ENDPOINT, NodeKind.ROUTE) and node.level:
        label += f" [{color}]· {node.level} {node.confidence}[/]"
    if node.tags:
        label += f" [{MUTED}]{' '.join(node.tags)}[/]"
    return label


def render_graph_tree(graph: Graph, *, max_nodes: int = 60) -> Tree:
    """Render a graph as a confidence-coloured Rich tree (deterministic)."""
    tree = Tree(f"[{NEON_RED}]◢ {graph.title.upper()} ◣[/]", guide_style=MUTED)
    if graph.empty:
        tree.add(f"[{MUTED}]no intelligence to map yet[/]")
        return tree

    rendered = 0

    def attach(parent_tree: Tree, node: Node, seen: frozenset[str]) -> None:
        nonlocal rendered
        if rendered >= max_nodes or node.id in seen:
            return
        branch = parent_tree.add(_node_markup(node))
        rendered += 1
        seen = seen | {node.id}
        for child in graph.children(node.id):   # already deterministically sorted
            attach(branch, child, seen)

    for root in graph.roots():
        attach(tree, root, frozenset())
    if rendered >= max_nodes:
        tree.add(f"[{MUTED}]… node limit reached[/]")
    return tree


def render_graph_legend(graph: Graph) -> Table:
    """A compact summary of a graph: node counts by kind."""
    g = Table.grid(expand=True, padding=(0, 1, 0, 0))
    g.add_column(justify="left", ratio=1)
    g.add_column(justify="right")
    counts = graph.counts_by_kind()
    if not counts:
        g.add_row(f"[{MUTED}]empty[/]", "")
        return g
    for kind, n in counts.items():
        glyph = _KIND_GLYPH.get(kind, "•")
        g.add_row(f"[{DIM_GREY}]{glyph} {kind}[/]", f"[{OFF_WHITE}]{n}[/]")
    return g
