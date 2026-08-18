"""Workspace & session management backed by SQLite.

A workspace groups everything about an engagement: endpoints, findings, notes,
recorded transactions, and scan history. Supports resume, export, and import.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.models import Endpoint, Finding
from ..utils.logging import get_logger

log = get_logger("workspace")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    target TEXT,
    tags TEXT,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(workspace_id, fingerprint),
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    fingerprint TEXT,
    data TEXT NOT NULL,
    created TEXT NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created TEXT NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT,
    target TEXT,
    endpoints INTEGER,
    findings INTEGER,
    duration REAL,
    status TEXT,
    created TEXT NOT NULL,
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
CREATE TABLE IF NOT EXISTS replays (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    rid INTEGER NOT NULL,
    data TEXT NOT NULL,
    created TEXT NOT NULL,
    UNIQUE(workspace_id, rid),
    FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class WorkspaceManager:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        # Concurrency hardening: the REPL and the Textual dashboard each hold their
        # own connection to this file (and a user may run two `spyder` processes).
        # WAL lets readers and the single writer coexist instead of blocking each
        # other, and a generous busy timeout makes a briefly-contended writer wait
        # rather than failing immediately with "database is locked".
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Bring an older workspace database up to the current schema in place.

        Adds the findings ``fingerprint`` column, backfills it from stored data,
        collapses pre-existing duplicate findings, then enforces uniqueness so
        repeated scans update a finding rather than appending an identical copy.
        Also adds the structured ``scan_history`` columns (target/endpoints/
        findings/duration/status) used by the history table.
        """
        # scan_history: structured columns for the history table.
        hist_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(scan_history)")}
        for col, decl in (
            ("target", "TEXT"),
            ("endpoints", "INTEGER"),
            ("findings", "INTEGER"),
            ("duration", "REAL"),
            ("status", "TEXT"),
        ):
            if col not in hist_cols:
                self.conn.execute(f"ALTER TABLE scan_history ADD COLUMN {col} {decl}")

        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(findings)")}
        if "fingerprint" not in cols:
            self.conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
        # Backfill any rows still missing a fingerprint (new column or legacy data).
        for row in self.conn.execute(
            "SELECT id, data FROM findings WHERE fingerprint IS NULL"
        ).fetchall():
            try:
                fp = Finding.model_validate_json(row["data"]).fingerprint()
            except Exception:  # unparseable legacy row — fall back to row identity
                fp = f"legacy-{row['id']}"
            self.conn.execute(
                "UPDATE findings SET fingerprint=? WHERE id=?", (fp, row["id"])
            )
        # Collapse historical duplicates, keeping the most recent row per identity.
        self.conn.execute(
            "DELETE FROM findings WHERE id NOT IN ("
            "  SELECT MAX(id) FROM findings GROUP BY workspace_id, fingerprint"
            ")"
        )
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_findings_identity "
            "ON findings(workspace_id, fingerprint)"
        )

    def close(self) -> None:
        self.conn.close()

    # --- workspaces ---
    def create(self, name: str, target: str | None = None, tags: list[str] | None = None) -> int:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT OR IGNORE INTO workspaces(name, target, tags, created) VALUES (?,?,?,?)",
                (name, target, json.dumps(tags or []), _now()),
            )
            self.conn.commit()
            cur.execute("SELECT id FROM workspaces WHERE name=?", (name,))
            return cur.fetchone()["id"]

    def list_workspaces(self) -> list[dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM workspaces ORDER BY created DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_id(self, name: str) -> int | None:
        cur = self.conn.execute("SELECT id FROM workspaces WHERE name=?", (name,))
        row = cur.fetchone()
        return row["id"] if row else None

    # --- endpoints ---
    def save_endpoints(self, ws_id: int, endpoints: list[Endpoint]) -> int:
        n = 0
        with closing(self.conn.cursor()) as cur:
            for ep in endpoints:
                cur.execute(
                    "INSERT OR IGNORE INTO endpoints(workspace_id, fingerprint, data) VALUES (?,?,?)",
                    (ws_id, ep.fingerprint(), ep.model_dump_json()),
                )
                n += cur.rowcount
            self.conn.commit()
        return n

    def get_endpoints(self, ws_id: int) -> list[Endpoint]:
        cur = self.conn.execute("SELECT data FROM endpoints WHERE workspace_id=?", (ws_id,))
        return [Endpoint.model_validate_json(r["data"]) for r in cur.fetchall()]

    # --- findings ---
    def save_finding(self, ws_id: int, finding: Finding) -> None:
        """Persist a finding, refreshing an existing record with the same identity.

        Identity is ``Finding.fingerprint()`` (source + severity + title +
        endpoint). Re-running a scan updates the stored copy in place instead of
        accumulating duplicates.
        """
        self.conn.execute(
            "INSERT INTO findings(workspace_id, severity, fingerprint, data, created) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(workspace_id, fingerprint) DO UPDATE SET "
            "severity=excluded.severity, data=excluded.data, created=excluded.created",
            (ws_id, finding.severity.value, finding.fingerprint(),
             finding.model_dump_json(), _now()),
        )
        self.conn.commit()

    def get_findings(self, ws_id: int) -> list[Finding]:
        cur = self.conn.execute("SELECT data FROM findings WHERE workspace_id=?", (ws_id,))
        return [Finding.model_validate_json(r["data"]) for r in cur.fetchall()]

    # --- notes & history ---
    def add_note(self, ws_id: int, body: str) -> None:
        self.conn.execute(
            "INSERT INTO notes(workspace_id, body, created) VALUES (?,?,?)", (ws_id, body, _now())
        )
        self.conn.commit()

    def get_notes(self, ws_id: int) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT body, created FROM notes WHERE workspace_id=? ORDER BY created", (ws_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    def log_scan(
        self,
        ws_id: int,
        kind: str,
        summary: str,
        *,
        target: str | None = None,
        endpoints: int | None = None,
        findings: int | None = None,
        duration: float | None = None,
        status: str | None = None,
    ) -> None:
        """Record a scan/connector run in this workspace's history.

        Repeated identical runs (same ``kind`` + ``target``) refresh the existing
        most-recent row in place rather than accumulating duplicate entries, so a
        history that is re-run many times stays readable and shows the latest
        counts/duration for each distinct activity.
        """
        with closing(self.conn.cursor()) as cur:
            # Refresh the most-recent history row for this (kind, target) in place,
            # wherever it sits in the timeline — otherwise interleaving a different
            # activity between two identical runs would leave stale duplicate rows.
            cur.execute(
                "SELECT id FROM scan_history WHERE workspace_id=? AND kind=? "
                "AND IFNULL(target,'')=IFNULL(?,'') ORDER BY id DESC LIMIT 1",
                (ws_id, kind, target),
            )
            dup = cur.fetchone()
            if dup is not None:
                cur.execute(
                    "UPDATE scan_history SET summary=?, endpoints=?, findings=?, "
                    "duration=?, status=?, created=? WHERE id=?",
                    (summary, endpoints, findings, duration, status, _now(), dup["id"]),
                )
            else:
                cur.execute(
                    "INSERT INTO scan_history"
                    "(workspace_id, kind, summary, target, endpoints, findings, "
                    " duration, status, created) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ws_id, kind, summary, target, endpoints, findings,
                     duration, status, _now()),
                )
            self.conn.commit()

    def history(self, ws_id: int) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT kind, summary, target, endpoints, findings, duration, status, created "
            "FROM scan_history WHERE workspace_id=? ORDER BY created",
            (ws_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    # --- replay records ---
    def save_replay(self, ws_id: int, rid: int, data: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO replays(workspace_id, rid, data, created) VALUES (?,?,?,?) "
            "ON CONFLICT(workspace_id, rid) DO UPDATE SET data=excluded.data",
            (ws_id, rid, json.dumps(data), _now()),
        )
        self.conn.commit()

    def get_replays(self, ws_id: int) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT data FROM replays WHERE workspace_id=? ORDER BY rid", (ws_id,)
        )
        return [json.loads(r["data"]) for r in cur.fetchall()]

    # --- export / import ---
    def export(self, ws_id: int) -> dict[str, Any]:
        return {
            "endpoints": [e.model_dump(mode="json") for e in self.get_endpoints(ws_id)],
            "findings": [f.model_dump(mode="json") for f in self.get_findings(ws_id)],
            "history": self.history(ws_id),
            "exported": _now(),
        }
