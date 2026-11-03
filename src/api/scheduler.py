"""Background worker that runs scheduled scans.

Started from the FastAPI lifespan unless ``ROUTER_SECURITY_SCHEDULER=0``.
Every ``poll_seconds`` it claims due schedules and runs them (at most
``max_concurrent`` at once) through the same assessment and persistence path
as interactive scans. Each resulting scan is tagged ``scheduled`` plus the
schedule's own tags, so History can filter them.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable, Dict, Optional

from database.credentials import CredentialError, CredentialVault
from database.schedules import ScheduleStore

logger = logging.getLogger(__name__)

SCHEDULED_TAG = "scheduled"
MAX_TAGS = 10  # matches ScanAnnotationUpdate


def scheduler_enabled() -> bool:
    return os.environ.get("ROUTER_SECURITY_SCHEDULER", "1").lower() not in ("0", "false", "no", "off")


def _default_run_scan(host: str, port: int, username: str, password: str):
    """Run one assessment and persist it. Returns (scan_id, risk_score)."""
    from api.routes import scan as scan_routes

    start = time.time()
    results = scan_routes._run_ssh_assessment(host, port, username, password)
    result = scan_routes._build_scan_result(results, host, time.time() - start)
    scan_id = scan_routes._persist_scan(result)
    return scan_id, result.risk_score


def _tag_scan(scan_id: int, tags: list) -> None:
    from database.scan_history import ScanHistoryDB

    merged = [SCHEDULED_TAG] + [t for t in tags if t != SCHEDULED_TAG]
    with ScanHistoryDB() as db:
        db.update_annotations(scan_id, tags=merged[:MAX_TAGS])


class Scheduler:
    def __init__(
        self,
        store: Optional[ScheduleStore] = None,
        vault: Optional[CredentialVault] = None,
        run_scan: Callable[..., Any] = _default_run_scan,
        poll_seconds: float = 30.0,
        max_concurrent: int = 2,
    ):
        self._store = store
        self._vault = vault
        self._run_scan = run_scan
        self.poll_seconds = poll_seconds
        self._sem = asyncio.Semaphore(max_concurrent)
        self._task: Optional[asyncio.Task] = None
        self._inflight: set = set()

    @property
    def store(self) -> ScheduleStore:
        if self._store is None:
            self._store = ScheduleStore()
        return self._store

    @property
    def vault(self) -> CredentialVault:
        if self._vault is None:
            self._vault = CredentialVault()
        return self._vault

    # -- one schedule -------------------------------------------------------

    def execute(self, schedule: Dict[str, Any]) -> Dict[str, Any]:
        """Run a claimed schedule synchronously and record the outcome."""
        sid = schedule["id"]
        try:
            password = self.vault.decrypt(schedule["credential"])
        except CredentialError as e:
            self.store.finish(sid, status="error", error=str(e))
            return {"status": "error", "error": str(e)}

        try:
            scan_id, risk = self._run_scan(schedule["target"], schedule["port"], schedule["username"], password)
        except ConnectionError as e:
            msg = str(e) or "SSH connection failed"
            self.store.finish(sid, status="error", error=msg)
            return {"status": "error", "error": msg}
        except Exception as e:  # never let one device kill the worker
            logger.exception("Scheduled scan %s (%s) failed", sid, schedule["target"])
            msg = f"Assessment failed: {e}"
            self.store.finish(sid, status="error", error=msg)
            return {"status": "error", "error": msg}

        if scan_id is None:
            msg = "Scan ran but could not be saved to history"
            self.store.finish(sid, status="error", error=msg, risk_score=risk)
            return {"status": "error", "error": msg}

        try:
            _tag_scan(scan_id, schedule.get("tags") or [])
        except Exception as e:  # tagging is cosmetic; keep the result
            logger.warning("Could not tag scheduled scan %s: %s", scan_id, e)

        self.store.finish(sid, status="ok", scan_id=scan_id, risk_score=risk)
        return {"status": "ok", "scan_id": scan_id, "risk_score": risk}

    async def _run_claimed(self, schedule: Dict[str, Any]) -> None:
        async with self._sem:
            await asyncio.to_thread(self.execute, schedule)

    def _spawn(self, schedule: Dict[str, Any]) -> asyncio.Task:
        task = asyncio.create_task(self._run_claimed(schedule))
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)
        return task

    # -- loop ---------------------------------------------------------------

    async def tick(self) -> list:
        """Claim everything due and start it. Returns the started tasks."""
        try:
            due = await asyncio.to_thread(self.store.claim_due)
        except Exception as e:
            logger.warning("Scheduler could not read schedules: %s", e)
            return []
        return [self._spawn(s) for s in due]

    async def run_now(self, schedule_id: int) -> Optional[asyncio.Task]:
        claimed = await asyncio.to_thread(self.store.claim, schedule_id)
        return self._spawn(claimed) if claimed else None

    async def _loop(self) -> None:
        while True:
            await self.tick()
            await asyncio.sleep(self.poll_seconds)

    def start(self) -> None:
        if self._task is None:
            reset = self.store.reset_running()
            if reset:
                logger.info("Cleared %d schedule(s) interrupted by a restart", reset)
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        for t in list(self._inflight):
            t.cancel()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()


_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        try:
            poll = max(1.0, float(os.environ.get("ROUTER_SECURITY_SCHEDULER_POLL", "30")))
        except ValueError:
            poll = 30.0
        _scheduler = Scheduler(poll_seconds=poll)
    return _scheduler


def set_scheduler(s: Optional[Scheduler]) -> None:
    """Test hook."""
    global _scheduler
    _scheduler = s
