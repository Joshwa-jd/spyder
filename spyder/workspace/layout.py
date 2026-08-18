"""Per-workspace on-disk layout — evidence, screenshots, notes, timeline.

The SQLite ``WorkspaceManager`` owns structured records (endpoints, findings,
history). This module owns the *filesystem* side of an engagement: a stable
directory per workspace for analyst artifacts that don't belong in the database —
captured evidence, screenshots, freeform notes, and a timeline log.

Kept project-local under ``<home>/workspaces/<name>/`` to match SPYDER's
project-local data convention.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..utils.paths import safe_slug


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class WorkspacePaths:
    """Resolves and provisions the artifact directories for one workspace."""

    root: Path

    @classmethod
    def for_workspace(cls, workspaces_dir: Path, name: str) -> WorkspacePaths:
        # Slugify: the workspace name must resolve to a single directory under
        # workspaces_dir and never escape it via '../' or an absolute path.
        return cls(root=workspaces_dir / safe_slug(name))

    # --- directories ---
    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def screenshots_dir(self) -> Path:
        return self.root / "screenshots"

    # --- files ---
    @property
    def notes_file(self) -> Path:
        return self.root / "notes.md"

    @property
    def timeline_file(self) -> Path:
        return self.root / "timeline.jsonl"

    @property
    def metadata_file(self) -> Path:
        return self.root / "metadata.json"

    def ensure(self) -> WorkspacePaths:
        """Create the directory tree and seed the notes file if missing."""
        for d in (self.root, self.evidence_dir, self.screenshots_dir):
            d.mkdir(parents=True, exist_ok=True)
        if not self.notes_file.exists():
            self.notes_file.write_text(
                f"# Workspace notes — {self.root.name}\n\n"
                "_Analyst notes for this engagement._\n",
                encoding="utf-8",
            )
        return self

    # --- notes ---
    def append_note(self, text: str) -> None:
        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        with self.notes_file.open("a", encoding="utf-8") as fh:
            fh.write(f"\n- `{stamp}` {text}\n")

    def read_notes(self) -> str:
        return self.notes_file.read_text(encoding="utf-8") if self.notes_file.exists() else ""

    # --- timeline (append-only JSONL, timeline-view preparation) ---
    def append_timeline(self, kind: str, summary: str, **extra) -> None:
        entry = {"ts": _utcnow_iso(), "kind": kind, "summary": summary, **extra}
        with self.timeline_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def read_timeline(self) -> list[dict]:
        if not self.timeline_file.exists():
            return []
        out: list[dict] = []
        for line in self.timeline_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    # --- metadata summary ---
    def write_metadata(self, **meta) -> None:
        meta.setdefault("updated", _utcnow_iso())
        self.metadata_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def read_metadata(self) -> dict:
        if not self.metadata_file.exists():
            return {}
        try:
            return json.loads(self.metadata_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def summary(self) -> dict:
        """Lightweight on-disk artifact summary for dashboard metadata panels."""
        def _count(p: Path) -> int:
            return sum(1 for _ in p.iterdir()) if p.exists() else 0

        return {
            "evidence": _count(self.evidence_dir),
            "screenshots": _count(self.screenshots_dir),
            "timeline_entries": len(self.read_timeline()),
            "has_notes": self.notes_file.exists(),
        }
