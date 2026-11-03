"""Scheduled scans: CRUD, run-now, and scheduler status.

Passwords are write-only: they are encrypted on the way in and never returned.
"""

from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from api.schemas import ScheduleCreate, ScheduleOut, SchedulerStatus, ScheduleUpdate

router = APIRouter()


def _store():
    from database.schedules import ScheduleStore

    return ScheduleStore()


def _vault():
    from database.credentials import CredentialError, CredentialVault

    try:
        return CredentialVault()
    except CredentialError as e:
        raise HTTPException(status_code=500, detail=str(e))


def _out(s: Dict[str, Any]) -> ScheduleOut:
    return ScheduleOut(
        **{k: v for k, v in s.items() if k in ScheduleOut.model_fields and k != "has_credential"},
        has_credential=bool(s.get("credential")),
    )


@router.get("/schedules", response_model=SchedulerStatus)
def list_schedules():
    from api.scheduler import get_scheduler, scheduler_enabled

    import os

    from database.credentials import default_key_file

    # Report where the key comes from without creating one on a read.
    if os.environ.get("ROUTER_SECURITY_SECRET_KEY"):
        key_source = "env"
    elif default_key_file().exists():
        key_source = "file"
    else:
        key_source = "not_created"

    scheduler = get_scheduler()
    return SchedulerStatus(
        enabled=scheduler_enabled(),
        running=scheduler.running,
        poll_seconds=scheduler.poll_seconds,
        key_source=key_source,
        schedules=[_out(s) for s in _store().list()],
    )


@router.post("/schedules", response_model=ScheduleOut, status_code=201)
async def create_schedule(body: ScheduleCreate):
    from database.schedules import utcnow

    vault = _vault()
    # The next regular run is one interval out; "run immediately" is an extra
    # run-now on top, so the worker doesn't see a schedule that's due forever.
    first = utcnow() + timedelta(minutes=body.interval_minutes)
    schedule = _store().create(
        target=body.target,
        port=body.port,
        username=body.username,
        credential=vault.encrypt(body.password),
        interval_minutes=body.interval_minutes,
        name=body.name,
        tags=body.tags,
        enabled=body.enabled,
        first_run_at=first,
    )
    if body.run_immediately and body.enabled:
        from api.scheduler import get_scheduler

        await get_scheduler().run_now(schedule["id"])
        schedule = _store().get(schedule["id"]) or schedule
    return _out(schedule)


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: int, body: ScheduleUpdate):
    from database.schedules import iso, utcnow

    store = _store()
    current = store.get(schedule_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    fields = body.model_dump(exclude_unset=True, exclude_none=True)
    password = fields.pop("password", None)
    if password is not None:
        fields["credential"] = _vault().encrypt(password)
    # A new interval takes effect from now rather than waiting out the old one.
    if "interval_minutes" in fields and fields["interval_minutes"] != current["interval_minutes"]:
        fields["next_run_at"] = iso(utcnow() + timedelta(minutes=fields["interval_minutes"]))
    # Re-enabling a long-paused schedule shouldn't fire immediately for a stale slot.
    if fields.get("enabled") and not current["enabled"] and "next_run_at" not in fields:
        fields["next_run_at"] = iso(utcnow() + timedelta(minutes=current["interval_minutes"]))

    if not fields:
        return _out(current)
    updated = store.update(schedule_id, **fields)
    if updated is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _out(updated)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int):
    if not _store().delete(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "deleted"}


@router.post("/schedules/{schedule_id}/run", response_model=ScheduleOut, status_code=202)
async def run_schedule_now(schedule_id: int):
    """Start a scheduled scan now (in the background). 409 if it's already running."""
    from api.scheduler import get_scheduler

    store = _store()
    if store.get(schedule_id) is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    task = await get_scheduler().run_now(schedule_id)
    if task is None:
        raise HTTPException(status_code=409, detail="This schedule is already running")
    return _out(store.get(schedule_id))
