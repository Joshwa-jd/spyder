"""Replay intelligence workbench — analyst-grade replay & request analysis.

Builds on the replay primitive (``HTTPClient.replay``) and the response diff
engine. A replayed request becomes a rich, serializable ``ReplayRecord`` carrying
both transaction snapshots, response/request header diffs, redirect tracking,
reflection tracking, timing deltas, and similarity — plus analyst metadata
(tags, notes, bookmarks, groups). ``ReplayHistory`` adds a search/filter pipeline
and aggregate analytics for the dashboard's replay widgets.

Strictly analytical: it compares and annotates requests the analyst already
issued. It does not mutate payloads or attack anything.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlparse

from ..http.client import Transaction
from ..validation.replay import filter_header_noise, replay_confidence
from .diff import ResponseDiff, diff


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _headers_ci(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def _anomaly_category(anomaly: str) -> str:
    """Reduce an anomaly string ('status 200→500', 'reflection×1') to its kind."""
    head = anomaly.split("×", 1)[0]
    return head.split(" ", 1)[0].strip() or "other"


# ---------------------------------------------------------------------------
# Header diffing
# ---------------------------------------------------------------------------


@dataclass
class HeaderDiff:
    added: list[tuple[str, str]] = field(default_factory=list)
    removed: list[tuple[str, str]] = field(default_factory=list)
    changed: list[tuple[str, str, str]] = field(default_factory=list)  # key, old, new

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)

    @property
    def empty(self) -> bool:
        return self.total == 0

    def to_dict(self) -> dict:
        return {"added": self.added, "removed": self.removed, "changed": self.changed}

    @classmethod
    def from_dict(cls, d: dict) -> HeaderDiff:
        return cls(
            added=[tuple(x) for x in d.get("added", [])],
            removed=[tuple(x) for x in d.get("removed", [])],
            changed=[tuple(x) for x in d.get("changed", [])],
        )


def diff_headers(old: dict[str, str], new: dict[str, str]) -> HeaderDiff:
    o, n = _headers_ci(old), _headers_ci(new)
    hd = HeaderDiff()
    for k, v in n.items():
        if k not in o:
            hd.added.append((k, v))
        elif o[k] != v:
            hd.changed.append((k, o[k], v))
    for k, v in o.items():
        if k not in n:
            hd.removed.append((k, v))
    hd.added.sort()
    hd.removed.sort()
    hd.changed.sort()
    return hd


# ---------------------------------------------------------------------------
# Transaction snapshots (serializable, body-bounded)
# ---------------------------------------------------------------------------


@dataclass
class TxnSnapshot:
    method: str
    url: str
    status: int | None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    body_len: int = 0
    elapsed_ms: float = 0.0
    content_type: str | None = None

    @classmethod
    def from_txn(cls, txn: Transaction, preview: int = 6000) -> TxnSnapshot:
        return cls(
            method=txn.method,
            url=txn.url,
            status=txn.status,
            request_headers=dict(txn.request_headers or {}),
            response_headers=dict(txn.response_headers or {}),
            body_preview=(txn.body or "")[:preview],
            body_len=len(txn.body or ""),
            elapsed_ms=round(txn.elapsed_ms, 2),
            content_type=(txn.response_headers or {}).get("content-type"),
        )

    def to_dict(self) -> dict:
        return {
            "method": self.method, "url": self.url, "status": self.status,
            "request_headers": self.request_headers, "response_headers": self.response_headers,
            "body_preview": self.body_preview, "body_len": self.body_len,
            "elapsed_ms": self.elapsed_ms, "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TxnSnapshot:
        return cls(
            method=d.get("method", "GET"), url=d.get("url", ""), status=d.get("status"),
            request_headers=d.get("request_headers", {}), response_headers=d.get("response_headers", {}),
            body_preview=d.get("body_preview", ""), body_len=d.get("body_len", 0),
            elapsed_ms=d.get("elapsed_ms", 0.0), content_type=d.get("content_type"),
        )


def _request_values(txn: Transaction) -> list[str]:
    """Extract submitted values (query + body) for reflection checking."""
    values: list[str] = []
    for _, v in parse_qsl(urlparse(txn.url).query):
        if v:
            values.append(v)
    if txn.request_body:
        # crude: split on common separators to catch form/json-ish values
        for chunk in str(txn.request_body).replace("&", " ").replace(",", " ").split():
            if "=" in chunk:
                chunk = chunk.split("=", 1)[1]
            chunk = chunk.strip("\"'{}[]: ")
            if len(chunk) >= 4:
                values.append(chunk)
    return values


def _reflected(values: list[str], body: str) -> list[str]:
    if not body:
        return []
    return sorted({v for v in values if len(v) >= 4 and v in body})


def _location(txn: Transaction) -> str | None:
    return _headers_ci(txn.response_headers or {}).get("location")


# ---------------------------------------------------------------------------
# ReplayRecord
# ---------------------------------------------------------------------------


@dataclass
class ReplayRecord:
    """A replayed request enriched with full comparison + analyst metadata."""

    index: int
    method: str
    url: str
    original_status: int | None
    replayed_status: int | None
    similarity: float
    length_delta: int
    timing_ms: float
    timing_delta_ms: float = 0.0
    notable: list[str] = field(default_factory=list)
    redirect_from: str | None = None
    redirect_to: str | None = None
    reflected: list[str] = field(default_factory=list)
    resp_header_diff: HeaderDiff = field(default_factory=HeaderDiff)
    req_header_diff: HeaderDiff = field(default_factory=HeaderDiff)
    original: TxnSnapshot | None = None
    replayed: TxnSnapshot | None = None
    confidence_score: int = 0
    confidence_level: str = "medium"
    anomalies: list[str] = field(default_factory=list)
    confidence_reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    when: datetime = field(default_factory=_utcnow)
    id: int = 0
    tags: list[str] = field(default_factory=list)
    note: str = ""
    bookmarked: bool = False
    group: str | None = None

    @property
    def status_changed(self) -> bool:
        return self.original_status != self.replayed_status

    @property
    def redirected(self) -> bool:
        return self.redirect_to is not None

    @property
    def anomalous(self) -> bool:
        return bool(self.anomalies)

    @property
    def stable(self) -> bool:
        """Replay reproduced an equivalent response (diffs are trustworthy)."""
        return not self.anomalies and self.confidence_score >= 55

    @property
    def clock(self) -> str:
        return self.when.strftime("%H:%M:%S")

    @property
    def status_flow(self) -> str:
        return f"{self.original_status}→{self.replayed_status}"

    @property
    def marker(self) -> str:
        """Single glyph summarising the record's state for timeline rendering."""
        if self.anomalous:
            return "⚠"
        if self.bookmarked:
            return "★"
        if self.stable:
            return "●"
        return "○"

    @property
    def label(self) -> str:
        return f"#{self.id} {self.method} {self.url}"

    def matches(self, query: str) -> bool:
        q = query.lower()
        return (
            q in self.url.lower()
            or q in self.method.lower()
            or q in str(self.original_status or "")
            or q in str(self.replayed_status or "")
            or q in self.note.lower()
            or any(q in t.lower() for t in self.tags)
            or (self.group is not None and q in self.group.lower())
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "index": self.index, "method": self.method, "url": self.url,
            "original_status": self.original_status, "replayed_status": self.replayed_status,
            "similarity": self.similarity, "length_delta": self.length_delta,
            "timing_ms": self.timing_ms, "timing_delta_ms": self.timing_delta_ms,
            "notable": self.notable, "redirect_from": self.redirect_from,
            "redirect_to": self.redirect_to, "reflected": self.reflected,
            "resp_header_diff": self.resp_header_diff.to_dict(),
            "req_header_diff": self.req_header_diff.to_dict(),
            "original": self.original.to_dict() if self.original else None,
            "replayed": self.replayed.to_dict() if self.replayed else None,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "anomalies": self.anomalies,
            "confidence_reasons": self.confidence_reasons,
            "evidence": self.evidence,
            "when": self.when.isoformat(),
            "tags": self.tags, "note": self.note,
            "bookmarked": self.bookmarked, "group": self.group,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ReplayRecord:
        when_raw = d.get("when")
        try:
            when = datetime.fromisoformat(when_raw) if when_raw else _utcnow()
        except ValueError:
            when = _utcnow()
        return cls(
            id=d.get("id", 0), index=d.get("index", 0),
            method=d.get("method", "GET"), url=d.get("url", ""),
            original_status=d.get("original_status"), replayed_status=d.get("replayed_status"),
            similarity=d.get("similarity", 0.0), length_delta=d.get("length_delta", 0),
            timing_ms=d.get("timing_ms", 0.0), timing_delta_ms=d.get("timing_delta_ms", 0.0),
            notable=d.get("notable", []), redirect_from=d.get("redirect_from"),
            redirect_to=d.get("redirect_to"), reflected=d.get("reflected", []),
            resp_header_diff=HeaderDiff.from_dict(d.get("resp_header_diff", {})),
            req_header_diff=HeaderDiff.from_dict(d.get("req_header_diff", {})),
            original=TxnSnapshot.from_dict(d["original"]) if d.get("original") else None,
            replayed=TxnSnapshot.from_dict(d["replayed"]) if d.get("replayed") else None,
            confidence_score=d.get("confidence_score", 0),
            confidence_level=d.get("confidence_level", "medium"),
            anomalies=d.get("anomalies", []),
            confidence_reasons=d.get("confidence_reasons", []),
            evidence=d.get("evidence", []),
            when=when, tags=d.get("tags", []), note=d.get("note", ""),
            bookmarked=d.get("bookmarked", False), group=d.get("group"),
        )


def record_replay(index: int, original: Transaction, replayed: Transaction, *, id: int = 0) -> ReplayRecord:
    """Build a fully enriched ReplayRecord from an original/replayed pair.

    Response-header diffs are de-noised (volatile headers like Date/Set-Cookie are
    ignored) before they feed the replay confidence score, so a replay only loses
    confidence for *meaningful* header changes.
    """
    d: ResponseDiff = diff(original, replayed)
    reflected = _reflected(_request_values(original), replayed.body or "")
    resp_diff = diff_headers(original.response_headers, replayed.response_headers)

    meaningful = (
        len(filter_header_noise(resp_diff.added))
        + len(filter_header_noise(resp_diff.removed))
        + len(filter_header_noise(resp_diff.changed))
    )
    rconf = replay_confidence(
        similarity=d.similarity,
        original_status=original.status,
        replayed_status=replayed.status,
        length_delta=d.length_delta,
        reflected=reflected,
        meaningful_header_changes=meaningful,
    )
    return ReplayRecord(
        id=id,
        index=index,
        method=replayed.method,
        url=replayed.url,
        original_status=original.status,
        replayed_status=replayed.status,
        similarity=d.similarity,
        length_delta=d.length_delta,
        timing_ms=round(replayed.elapsed_ms, 1),
        timing_delta_ms=d.timing_delta_ms,
        notable=list(d.notable),
        redirect_from=_location(original),
        redirect_to=_location(replayed),
        reflected=reflected,
        resp_header_diff=resp_diff,
        req_header_diff=diff_headers(original.request_headers, replayed.request_headers),
        original=TxnSnapshot.from_txn(original),
        replayed=TxnSnapshot.from_txn(replayed),
        confidence_score=rconf.score,
        confidence_level=rconf.level.value,
        anomalies=rconf.anomalies,
        confidence_reasons=rconf.reasons,
        evidence=rconf.sources,
    )


# ---------------------------------------------------------------------------
# Replay analytics
# ---------------------------------------------------------------------------


@dataclass
class ReplayAnalytics:
    total: int = 0
    bookmarked: int = 0
    status_changes: int = 0
    redirects: int = 0
    with_reflection: int = 0
    avg_timing_ms: float = 0.0
    min_timing_ms: float = 0.0
    max_timing_ms: float = 0.0
    avg_similarity: float = 0.0
    avg_confidence: float = 0.0
    stable: int = 0
    anomalous: int = 0
    status_distribution: dict[str, int] = field(default_factory=dict)
    timing_series: list[float] = field(default_factory=list)
    confidence_series: list[int] = field(default_factory=list)
    tag_counts: dict[str, int] = field(default_factory=dict)
    anomaly_counts: dict[str, int] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return self.total == 0

    @property
    def stability_pct(self) -> float:
        """Share of replays that reproduced an equivalent, trustworthy response."""
        return round(100.0 * self.stable / self.total, 1) if self.total else 0.0


# ---------------------------------------------------------------------------
# ReplayHistory — search / filter / analytics / persistence
# ---------------------------------------------------------------------------


class ReplayHistory:
    """Replay records with analyst workflow: search, filter, tag, bookmark, group."""

    def __init__(self) -> None:
        self._records: list[ReplayRecord] = []
        self._next_id = 1

    # --- mutation ---
    def add(self, record: ReplayRecord) -> ReplayRecord:
        if not record.id:
            record.id = self._next_id
        self._next_id = max(self._next_id, record.id + 1)
        self._records.append(record)
        return record

    def load_record(self, record: ReplayRecord) -> ReplayRecord:
        """Load a persisted record (preserves its id)."""
        return self.add(record)

    def get(self, rid: int) -> ReplayRecord | None:
        return next((r for r in self._records if r.id == rid), None)

    def tag(self, rid: int, *tags: str) -> ReplayRecord | None:
        rec = self.get(rid)
        if rec:
            for t in tags:
                if t and t not in rec.tags:
                    rec.tags.append(t)
        return rec

    def untag(self, rid: int, tag: str) -> ReplayRecord | None:
        rec = self.get(rid)
        if rec and tag in rec.tags:
            rec.tags.remove(tag)
        return rec

    def bookmark(self, rid: int, on: bool = True) -> ReplayRecord | None:
        rec = self.get(rid)
        if rec:
            rec.bookmarked = on
        return rec

    def annotate(self, rid: int, note: str) -> ReplayRecord | None:
        rec = self.get(rid)
        if rec:
            rec.note = note
        return rec

    def set_group(self, rid: int, group: str | None) -> ReplayRecord | None:
        rec = self.get(rid)
        if rec:
            rec.group = group
        return rec

    # --- query ---
    @property
    def records(self) -> list[ReplayRecord]:
        return list(self._records)

    def search(self, query: str) -> list[ReplayRecord]:
        return [r for r in self._records if r.matches(query)]

    def filter(
        self,
        query: str | None = None,
        tag: str | None = None,
        bookmarked: bool | None = None,
        status_changed: bool | None = None,
        redirected: bool | None = None,
        reflected: bool | None = None,
        group: str | None = None,
    ) -> list[ReplayRecord]:
        out = self._records
        if query:
            out = [r for r in out if r.matches(query)]
        if tag is not None:
            out = [r for r in out if tag in r.tags]
        if bookmarked is not None:
            out = [r for r in out if r.bookmarked == bookmarked]
        if status_changed is not None:
            out = [r for r in out if r.status_changed == status_changed]
        if redirected is not None:
            out = [r for r in out if r.redirected == redirected]
        if reflected is not None:
            out = [r for r in out if bool(r.reflected) == reflected]
        if group is not None:
            out = [r for r in out if r.group == group]
        return list(out)

    def latest(self, limit: int = 20) -> list[ReplayRecord]:
        return self._records[-limit:][::-1]

    def bookmarks(self) -> list[ReplayRecord]:
        return [r for r in self._records if r.bookmarked]

    def groups(self) -> dict[str, list[ReplayRecord]]:
        out: dict[str, list[ReplayRecord]] = {}
        for r in self._records:
            if r.group:
                out.setdefault(r.group, []).append(r)
        return out

    def all_tags(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for r in self._records:
            c.update(r.tags)
        return dict(c)

    # --- analytics ---
    def analytics(self) -> ReplayAnalytics:
        if not self._records:
            return ReplayAnalytics()
        timings = [r.timing_ms for r in self._records]
        sims = [r.similarity for r in self._records]
        confs = [r.confidence_score for r in self._records]
        status_dist: Counter[str] = Counter()
        anomaly_dist: Counter[str] = Counter()
        for r in self._records:
            status_dist[r.status_flow] += 1
            for a in r.anomalies:
                anomaly_dist[_anomaly_category(a)] += 1
        return ReplayAnalytics(
            total=len(self._records),
            bookmarked=sum(1 for r in self._records if r.bookmarked),
            status_changes=sum(1 for r in self._records if r.status_changed),
            redirects=sum(1 for r in self._records if r.redirected),
            with_reflection=sum(1 for r in self._records if r.reflected),
            avg_timing_ms=round(sum(timings) / len(timings), 1),
            min_timing_ms=round(min(timings), 1),
            max_timing_ms=round(max(timings), 1),
            avg_similarity=round(sum(sims) / len(sims), 4),
            avg_confidence=round(sum(confs) / len(confs), 1),
            stable=sum(1 for r in self._records if r.stable),
            anomalous=sum(1 for r in self._records if r.anomalous),
            status_distribution=dict(status_dist),
            timing_series=timings,
            confidence_series=confs,
            tag_counts=self.all_tags(),
            anomaly_counts=dict(anomaly_dist),
        )

    def timeline(self, limit: int = 30) -> list[ReplayRecord]:
        """Records in chronological (issue) order, oldest→newest, capped at ``limit``.

        Ordered by record id — the deterministic creation order — so the timeline
        is reproducible regardless of wall-clock ``when`` jitter across sessions.
        """
        ordered = sorted(self._records, key=lambda r: r.id)
        return ordered[-limit:]

    def anomaly_breakdown(self) -> dict[str, int]:
        """Count of anomalous replays per anomaly category (deterministic order)."""
        c: Counter[str] = Counter()
        for r in self._records:
            for a in r.anomalies:
                c[_anomaly_category(a)] += 1
        return dict(sorted(c.items()))

    # --- persistence ---
    def to_list(self) -> list[dict]:
        return [r.to_dict() for r in self._records]

    def __len__(self) -> int:
        return len(self._records)
