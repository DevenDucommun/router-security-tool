"""Scan schedules, stored in the history database (table ``schedules``).

A schedule is a device + credentials + interval. The scheduler claims due
schedules atomically (``claim_due``), runs them, and records the outcome
(``finish``). Passwords are stored only as CredentialVault tokens.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 30 * 24 * 60

_COLUMNS = (
    "id, name, target, port, username, credential, interval_minutes, enabled, tags, "
    "next_run_at, last_run_at, last_status, last_scan_id, last_error, last_risk_score, "
    "running, created_at, updated_at"
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _default_path() -> Path:
    return Path(
        os.environ.get("ROUTER_SECURITY_DB")
        or Path(__file__).parent.parent.parent / "data" / "scan_history.db"
    )


class ScheduleStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.path = Path(db_path) if db_path else _default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS schedules (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           name TEXT NOT NULL DEFAULT '',
                           target TEXT NOT NULL,
                           port INTEGER NOT NULL DEFAULT 22,
                           username TEXT NOT NULL,
                           credential TEXT NOT NULL,
                           interval_minutes INTEGER NOT NULL,
                           enabled INTEGER NOT NULL DEFAULT 1,
                           tags TEXT NOT NULL DEFAULT '[]',
                           next_run_at TEXT NOT NULL,
                           last_run_at TEXT,
                           last_status TEXT NOT NULL DEFAULT 'never',
                           last_scan_id INTEGER,
                           last_error TEXT,
                           last_risk_score REAL,
                           running INTEGER NOT NULL DEFAULT 0,
                           created_at TEXT NOT NULL,
                           updated_at TEXT NOT NULL
                       )"""
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules (enabled, running, next_run_at)"
                )
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        d["running"] = bool(d["running"])
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except (TypeError, ValueError):
            d["tags"] = []
        return d

    # -- CRUD ---------------------------------------------------------------

    def create(
        self,
        *,
        target: str,
        username: str,
        credential: str,
        interval_minutes: int,
        port: int = 22,
        name: str = "",
        tags: Optional[List[str]] = None,
        enabled: bool = True,
        first_run_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        now = utcnow()
        conn = self._connect()
        try:
            cur = conn.execute(
                """INSERT INTO schedules (name, target, port, username, credential, interval_minutes,
                                          enabled, tags, next_run_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    name, target, port, username, credential, interval_minutes, int(enabled),
                    json.dumps(tags or []), iso(first_run_at or now), iso(now), iso(now),
                ),
            )
            return self.get(cur.lastrowid, conn=conn)
        finally:
            conn.close()

    def get(self, schedule_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict[str, Any]]:
        own = conn is None
        conn = conn or self._connect()
        try:
            row = conn.execute(f"SELECT {_COLUMNS} FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
            return self._row(row) if row else None
        finally:
            if own:
                conn.close()

    def list(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(f"SELECT {_COLUMNS} FROM schedules ORDER BY target, id").fetchall()
            return [self._row(r) for r in rows]
        finally:
            conn.close()

    _UPDATABLE = {"name", "port", "username", "credential", "interval_minutes", "enabled", "tags", "next_run_at"}

    def update(self, schedule_id: int, **fields: Any) -> Optional[Dict[str, Any]]:
        unknown = set(fields) - self._UPDATABLE
        if unknown:
            raise ValueError(f"Unknown schedule fields: {sorted(unknown)}")
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"] or [])
        if "enabled" in fields:
            fields["enabled"] = int(bool(fields["enabled"]))
        if "next_run_at" in fields and isinstance(fields["next_run_at"], datetime):
            fields["next_run_at"] = iso(fields["next_run_at"])
        fields["updated_at"] = iso(utcnow())
        assignments = ", ".join(f"{k} = ?" for k in fields)
        conn = self._connect()
        try:
            cur = conn.execute(
                f"UPDATE schedules SET {assignments} WHERE id = ?", (*fields.values(), schedule_id)
            )
            if cur.rowcount == 0:
                return None
            return self.get(schedule_id, conn=conn)
        finally:
            conn.close()

    def delete(self, schedule_id: int) -> bool:
        conn = self._connect()
        try:
            return conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,)).rowcount > 0
        finally:
            conn.close()

    # -- Scheduler hooks ----------------------------------------------------

    def claim_due(self, now: Optional[datetime] = None, limit: int = 32) -> List[Dict[str, Any]]:
        """Atomically mark due, enabled, idle schedules as running and push their next run.

        The next run is ``now + interval`` (not "previous slot + interval"), so a
        server that was down for a week runs each schedule once, not seven times.
        """
        now = now or utcnow()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                f"""SELECT {_COLUMNS} FROM schedules
                    WHERE enabled = 1 AND running = 0 AND next_run_at <= ?
                    ORDER BY next_run_at LIMIT ?""",
                (iso(now), limit),
            ).fetchall()
            claimed = []
            for row in rows:
                nxt = now + timedelta(minutes=row["interval_minutes"])
                conn.execute(
                    "UPDATE schedules SET running = 1, last_status = 'running', next_run_at = ?, "
                    "updated_at = ? WHERE id = ?",
                    (iso(nxt), iso(now), row["id"]),
                )
                claimed.append(self._row(row) | {"next_run_at": iso(nxt), "running": True})
            conn.execute("COMMIT")
            return claimed
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def claim(self, schedule_id: int, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        """Claim one schedule for an immediate run (keeps its next_run_at). None if busy/missing."""
        now = now or utcnow()
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE schedules SET running = 1, last_status = 'running', updated_at = ? "
                "WHERE id = ? AND running = 0",
                (iso(now), schedule_id),
            )
            if cur.rowcount == 0:
                return None
            return self.get(schedule_id, conn=conn)
        finally:
            conn.close()

    def finish(
        self,
        schedule_id: int,
        *,
        status: str,
        scan_id: Optional[int] = None,
        error: Optional[str] = None,
        risk_score: Optional[float] = None,
        at: Optional[datetime] = None,
    ) -> None:
        at = at or utcnow()
        conn = self._connect()
        try:
            conn.execute(
                """UPDATE schedules SET running = 0, last_status = ?, last_run_at = ?, last_scan_id = ?,
                       last_error = ?, last_risk_score = ?, updated_at = ? WHERE id = ?""",
                (status, iso(at), scan_id, error, risk_score, iso(at), schedule_id),
            )
        finally:
            conn.close()

    def reset_running(self) -> int:
        """After a crash/restart nothing is actually running; clear stale flags."""
        conn = self._connect()
        try:
            return conn.execute(
                "UPDATE schedules SET running = 0, last_status = 'error', "
                "last_error = 'Interrupted by server restart' WHERE running = 1"
            ).rowcount
        finally:
            conn.close()
