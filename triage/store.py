"""SQLite storage. One table, JSON column for the triage result."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from .models import ExistingReport, ReportIn, ReportRecord, Status, TriageResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    reporter    TEXT,
    source      TEXT NOT NULL,
    status      TEXT NOT NULL,
    triage_json TEXT,
    notes_json  TEXT NOT NULL DEFAULT '[]',
    error       TEXT
);
"""


class ReportStore:
    def __init__(self, path: str = "triage.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    def add(self, report: ReportIn) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO reports (created_at, title, body, reporter, source, status) VALUES (?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), report.title,
                 report.body, report.reporter, report.source, Status.received.value),
            )
            return int(cur.lastrowid)

    def save_triage(self, report_id: int, result: TriageResult, status: Status, notes: list[str]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE reports SET triage_json=?, status=?, notes_json=?, error=NULL WHERE id=?",
                (result.model_dump_json(), status.value, json.dumps(notes), report_id),
            )

    def mark_failed(self, report_id: int, error: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE reports SET status=?, error=? WHERE id=?",
                (Status.needs_review.value, error, report_id),
            )

    def set_status(self, report_id: int, status: Status) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE reports SET status=? WHERE id=?", (status.value, report_id))

    def get(self, report_id: int) -> ReportRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        return _to_record(row) if row else None

    def list(self, status: Status | None = None, limit: int = 100) -> list[ReportRecord]:
        sql, args = "SELECT * FROM reports", []
        if status:
            sql += " WHERE status=?"
            args.append(status.value)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [_to_record(r) for r in rows]

    def candidates_for_dedupe(self, exclude_id: int, limit: int = 25) -> list[ExistingReport]:
        """Recent triaged, non-duplicate reports: what a new report could duplicate."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM reports WHERE id != ? AND triage_json IS NOT NULL AND status != ? "
                "ORDER BY id DESC LIMIT ?",
                (exclude_id, Status.duplicate.value, limit),
            ).fetchall()
        out = []
        for r in rows:
            t = TriageResult.model_validate_json(r["triage_json"])
            out.append(ExistingReport(id=r["id"], title=r["title"], summary=t.summary,
                                      vuln_class=t.vuln_class.value,
                                      affected_component=t.affected_component))
        return out


def _to_record(row: sqlite3.Row) -> ReportRecord:
    return ReportRecord(
        id=row["id"], created_at=row["created_at"], title=row["title"], body=row["body"],
        reporter=row["reporter"], source=row["source"], status=Status(row["status"]),
        triage=TriageResult.model_validate_json(row["triage_json"]) if row["triage_json"] else None,
        notes=json.loads(row["notes_json"]), error=row["error"],
    )
