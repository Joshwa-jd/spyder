"""Deterministic intelligence graphs — the visual recon engine's foundation.

This module turns flat recon intelligence (endpoints, classes, technologies, JS
routes) into *graphs*: hosts that contain route groups that contain endpoints,
endpoints clustered by attack-surface class, technologies attributed to a host.
A graph is then laid out into reproducible coordinates that the dashboard renders
as a tree and reports render as an SVG.

The whole module is **pure and deterministic** — no I/O, clocks, randomness, or
set-iteration leaks. The same intelligence always yields:

  * the same node IDs (a stable hash of the node's canonical key),
  * the same node/edge ordering (sorted by ID),
  * the same layered layout coordinates (a structural sort, not insertion order).

That reproducibility is what lets an analyst trust that a diagram reflects the
intelligence and not an accident of dict ordering — and it is what makes the
graph tests meaningful (byte-identical output across runs).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

from ..validation.confidence import level_for_score
from ..validation.normalize import route_template
from .intel import EndpointClass, EndpointIntel


class NodeKind(StrEnum):
    HOST = "host"          # scheme://netloc root
    GROUP = "group"        # a route-path segment (an API/route grouping)
    ENDPOINT = "endpoint"  # a concrete (templated) endpoint leaf
    CLUSTER = "cluster"    # an attack-surface class grouping (auth/admin/…)
    TECH = "tech"          # an attributed technology
    ROUTE = "route"        # a JS-discovered route


class EdgeKind(StrEnum):
    CONTAINS = "contains"  # parent route contains child route/endpoint
    GROUPS = "groups"      # a cluster groups an endpoint
    USES = "uses"          # a host uses a technology


def _sid(kind: NodeKind, key: str) -> str:
    """Stable, collision-resistant node ID from its kind + canonical key."""
    digest = hashlib.sha1(f"{kind.value}|{key}".encode()).hexdigest()
    return f"{kind.value[:2]}_{digest[:12]}"


def _clamp_score(value: float) -> int:
    return max(0, min(100, int(value)))


# ---------------------------------------------------------------------------
# Graph model
# ---------------------------------------------------------------------------


@dataclass
class Node:
    """A graph node. Identity is its ``id``; mergeable, confidence-aware."""

    id: str
    kind: NodeKind
    label: str
    confidence: int = 0
    level: str = ""
    weight: int = 1
    tags: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind.value, "label": self.label,
            "confidence": self.confidence, "level": self.level,
            "weight": self.weight, "tags": list(self.tags), "detail": self.detail,
        }


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: EdgeKind = EdgeKind.CONTAINS

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "kind": self.kind.value}


@dataclass
class Graph:
    """A deterministic intelligence graph (nodes keyed by stable id)."""

    title: str = "intelligence"
    _nodes: dict[str, Node] = field(default_factory=dict)
    _edges: set[Edge] = field(default_factory=set)

    # --- construction ---
    def add_node(self, node: Node) -> Node:
        """Insert a node, merging into any existing node with the same id.

        Merge keeps the highest confidence/weight and unions tags so that the
        same logical node observed from several inputs converges deterministically
        regardless of the order it was added.
        """
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return node
        existing.confidence = max(existing.confidence, node.confidence)
        existing.weight = max(existing.weight, node.weight)
        if node.confidence >= existing.confidence:
            existing.level = node.level or existing.level
        existing.tags = tuple(sorted(set(existing.tags) | set(node.tags)))
        if node.detail and not existing.detail:
            existing.detail = node.detail
        return existing

    def add_edge(self, source: str, target: str, kind: EdgeKind = EdgeKind.CONTAINS) -> None:
        if source != target:
            self._edges.add(Edge(source, target, kind))

    # --- queries (always deterministically ordered) ---
    @property
    def nodes(self) -> list[Node]:
        return [self._nodes[k] for k in sorted(self._nodes)]

    @property
    def edges(self) -> list[Edge]:
        return sorted(self._edges, key=lambda e: (e.source, e.target, e.kind.value))

    def get(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def children(self, node_id: str) -> list[Node]:
        kids = [e.target for e in self._edges if e.source == node_id]
        return [self._nodes[t] for t in sorted(set(kids)) if t in self._nodes]

    def roots(self) -> list[Node]:
        """Nodes with no incoming edge (deterministically ordered)."""
        targets = {e.target for e in self._edges}
        return [n for n in self.nodes if n.id not in targets]

    @property
    def empty(self) -> bool:
        return not self._nodes

    def counts_by_kind(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self._nodes.values():
            out[n.kind.value] = out.get(n.kind.value, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


# ---------------------------------------------------------------------------
# Confidence helpers
# ---------------------------------------------------------------------------


def _endpoint_confidence(intel: EndpointIntel, override: int | None) -> tuple[int, str]:
    """Resolve a 0–100 confidence + level for an endpoint node."""
    if override is not None:
        score = _clamp_score(override)
    else:
        # Derive from the interest score; live (2xx) endpoints read as stronger.
        base = _clamp_score(intel.score)
        status = intel.endpoint.status
        if status and 200 <= status < 300:
            base = _clamp_score(base + 15)
        elif status and status >= 400:
            base = _clamp_score(base - 15)
        score = base
    return score, level_for_score(score).value


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_attack_surface_graph(
    intel: list[EndpointIntel],
    *,
    confidence_by_url: dict[str, int] | None = None,
    title: str = "attack-surface",
) -> Graph:
    """Host → route-group → endpoint containment tree (API dependency mapping).

    Paths are templated (``/users/42`` → ``/users/{id}``) so id-variant routes
    collapse into one logical branch. Intermediate route groups are real nodes,
    so the tree expresses which routes nest under which — a dependency map of the
    API surface. Each node carries a confidence so the diagram can be heat-mapped.
    """
    confidence_by_url = confidence_by_url or {}
    g = Graph(title=title)
    # Sort endpoints for a fully reproducible build order.
    ordered = sorted(intel, key=lambda it: (it.endpoint.url, it.endpoint.method.value))
    for it in ordered:
        ep = it.endpoint
        parts = urlsplit(ep.url)
        host = f"{parts.scheme}://{parts.netloc}" if parts.scheme else parts.netloc
        if not host:
            host = "(local)"
        host_node = g.add_node(Node(_sid(NodeKind.HOST, host), NodeKind.HOST, host))

        template = route_template(parts.path or "/")
        score, level = _endpoint_confidence(it, confidence_by_url.get(ep.url))

        # Walk path segments, creating/linking a group node per accumulated path.
        segments = [s for s in template.split("/") if s]
        parent_id = host_node.id
        accumulated = ""
        for seg in segments[:-1] if segments else []:
            accumulated += "/" + seg
            gid = _sid(NodeKind.GROUP, f"{host}{accumulated}")
            g.add_node(Node(gid, NodeKind.GROUP, accumulated, confidence=score, level=level))
            g.add_edge(parent_id, gid, EdgeKind.CONTAINS)
            parent_id = gid

        leaf_path = template if template != "/" else "/"
        leaf_key = f"{ep.method.value} {host}{leaf_path}"
        cls_tags = tuple(sorted(c.value for c in it.classes))
        leaf = g.add_node(Node(
            _sid(NodeKind.ENDPOINT, leaf_key), NodeKind.ENDPOINT,
            f"{ep.method.value} {leaf_path}",
            confidence=score, level=level, tags=cls_tags,
            detail=", ".join(it.reasons[:3]),
        ))
        g.add_edge(parent_id, leaf.id, EdgeKind.CONTAINS)
    return g


def build_cluster_graph(
    intel: list[EndpointIntel],
    *,
    confidence_by_url: dict[str, int] | None = None,
    include_static: bool = False,
    title: str = "endpoint-clusters",
) -> Graph:
    """Group endpoints by attack-surface class (auth/admin/api/…).

    A ``surface`` root contains one cluster node per :class:`EndpointClass`, each
    containing its endpoints. Cluster weight is the endpoint count; cluster
    confidence is the max of its members (the most trustworthy lead in the group).
    """
    confidence_by_url = confidence_by_url or {}
    g = Graph(title=title)
    root = g.add_node(Node(_sid(NodeKind.HOST, "surface"), NodeKind.HOST, "surface"))
    ordered = sorted(intel, key=lambda it: (it.endpoint.url, it.endpoint.method.value))
    for it in ordered:
        ep = it.endpoint
        # Primary class: the highest-weight class, else GENERIC.
        classes = [c for c in it.classes if include_static or c != EndpointClass.STATIC]
        if not classes:
            classes = [EndpointClass.GENERIC]
        primary = classes[0]
        score, level = _endpoint_confidence(it, confidence_by_url.get(ep.url))

        cid = _sid(NodeKind.CLUSTER, primary.value)
        cluster = g.add_node(Node(cid, NodeKind.CLUSTER, primary.value, level=level))
        cluster.weight += 1
        cluster.confidence = max(cluster.confidence, score)
        cluster.level = level_for_score(cluster.confidence).value
        g.add_edge(root.id, cid, EdgeKind.CONTAINS)

        template = route_template(ep.url)
        leaf_key = f"{ep.method.value} {template}"
        leaf = g.add_node(Node(
            _sid(NodeKind.ENDPOINT, leaf_key), NodeKind.ENDPOINT,
            f"{ep.method.value} {urlsplit(template).path or template}",
            confidence=score, level=level, tags=tuple(sorted(c.value for c in classes)),
        ))
        g.add_edge(cid, leaf.id, EdgeKind.GROUPS)
    # Normalise cluster weights to the number of grouped endpoints.
    for n in g.nodes:
        if n.kind is NodeKind.CLUSTER:
            n.weight = len(g.children(n.id))
    return g


def build_tech_graph(
    technologies: dict[str, str],
    *,
    host: str = "target",
    title: str = "technology-map",
) -> Graph:
    """Host → technology attribution map (technology relationship mapping)."""
    g = Graph(title=title)
    root = g.add_node(Node(_sid(NodeKind.HOST, host), NodeKind.HOST, host))
    for kind, value in sorted(technologies.items()):
        if not value:
            continue
        label = f"{kind}: {value}"
        tid = _sid(NodeKind.TECH, label)
        # Header-attributed tech is observed fact → high confidence.
        g.add_node(Node(tid, NodeKind.TECH, label, confidence=85, level="high", detail=kind))
        g.add_edge(root.id, tid, EdgeKind.USES)
    return g


def build_js_route_graph(
    routes: list[str] | set[str],
    *,
    title: str = "js-routes",
) -> Graph:
    """Group JS-discovered routes into a host → segment → route tree."""
    g = Graph(title=title)
    for raw in sorted(set(routes)):
        if not raw:
            continue
        parts = urlsplit(raw)
        host = f"{parts.scheme}://{parts.netloc}" if parts.scheme else "(relative)"
        host_node = g.add_node(Node(_sid(NodeKind.HOST, host), NodeKind.HOST, host))
        template = route_template(parts.path or raw)
        segments = [s for s in template.split("/") if s]
        parent_id = host_node.id
        accumulated = ""
        for seg in segments[:-1]:
            accumulated += "/" + seg
            gid = _sid(NodeKind.GROUP, f"js:{host}{accumulated}")
            g.add_node(Node(gid, NodeKind.GROUP, accumulated, confidence=45, level="medium"))
            g.add_edge(parent_id, gid, EdgeKind.CONTAINS)
            parent_id = gid
        leaf_label = "/" + "/".join(segments) if segments else template
        rid = _sid(NodeKind.ROUTE, f"js:{host}{leaf_label}")
        g.add_node(Node(rid, NodeKind.ROUTE, leaf_label, confidence=45, level="medium"))
        g.add_edge(parent_id, rid, EdgeKind.CONTAINS)
    return g


# ---------------------------------------------------------------------------
# Deterministic layered layout
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Placed:
    """A node positioned on the layout grid."""

    node: Node
    depth: int      # column / tree depth (0 = root)
    order: int      # row within the whole layout (0-based, top to bottom)


@dataclass
class Layout:
    placed: list[Placed] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    width: int = 0    # number of depth columns
    height: int = 0   # number of rows

    def position(self, node_id: str) -> Placed | None:
        return next((p for p in self.placed if p.node.id == node_id), None)


def layered_layout(graph: Graph) -> Layout:
    """Assign each node a (depth, order) by a structural depth-first walk.

    The walk starts from sorted roots and visits children sorted by (label, id),
    so the resulting row ordering depends only on graph *content*, never on the
    order nodes were inserted — identical graphs lay out identically.
    """
    layout = Layout(edges=graph.edges)
    if graph.empty:
        return layout

    placed: list[Placed] = []
    seen: set[str] = set()
    counter = 0

    def visit(node: Node, depth: int) -> None:
        nonlocal counter
        if node.id in seen:
            return
        seen.add(node.id)
        placed.append(Placed(node=node, depth=depth, order=counter))
        counter += 1
        kids = sorted(graph.children(node.id), key=lambda n: (n.label, n.id))
        for kid in kids:
            visit(kid, depth + 1)

    for root in graph.roots():
        visit(root, 0)
    # Any nodes unreachable from a root (shouldn't happen for trees) get appended.
    for node in graph.nodes:
        if node.id not in seen:
            visit(node, 0)

    layout.placed = placed
    layout.width = max((p.depth for p in placed), default=0) + 1
    layout.height = len(placed)
    return layout
