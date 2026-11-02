from contextlib import contextmanager
from typing import Optional

from fastapi import APIRouter, HTTPException

from api.schemas import ScanHistoryEntry, HistoryStats, ScanDiff, ScanAnnotationUpdate

router = APIRouter()


def _get_db():
    from database.scan_history import ScanHistoryDB
    return ScanHistoryDB()


@contextmanager
def _db():
    """Open a history DB for one request and always close it."""
    db = _get_db()
    try:
        yield db
    finally:
        db.close()


def _entry(s: dict) -> ScanHistoryEntry:
    return ScanHistoryEntry(
        id=s["id"],
        target=s["target"],
        scan_timestamp=s["scan_timestamp"],
        risk_score=s["risk_score"],
        vulnerability_count=s["vulnerability_count"],
        risk_level=s["risk_level"],
        device_vendor=s.get("device_vendor") or "",
        device_model=s.get("device_model") or "",
        tags=s.get("tags") or [],
        notes=s.get("notes") or "",
    )


@router.get("/history", response_model=list[ScanHistoryEntry])
async def get_history(
    limit: int = 50,
    target: Optional[str] = None,
    risk_level: Optional[str] = None,
    tag: Optional[str] = None,
):
    try:
        with _db() as db:
            scans = db.get_all_scans(limit=limit, target=target, risk_level=risk_level, tag=tag)
        return [_entry(s) for s in scans]
    except Exception:
        return []


@router.get("/history/stats", response_model=HistoryStats)
async def get_history_stats():
    try:
        with _db() as db:
            stats = db.get_statistics()
        return HistoryStats(
            total_scans=stats.get("total_scans", 0),
            unique_targets=stats.get("unique_targets", 0),
            total_vulnerabilities=stats.get("total_vulnerabilities", 0),
            avg_risk_score=stats.get("avg_risk_score", 0.0),
            risk_distribution=stats.get("risk_distribution", {}),
        )
    except Exception:
        return HistoryStats()


@router.get("/history/tags", response_model=list[str])
async def get_history_tags():
    try:
        with _db() as db:
            return db.get_all_tags()
    except Exception:
        return []


def _load_for_diff(db, scan_id: int) -> dict:
    summary = db.get_scan_summary(scan_id)
    full = db.get_scan_by_id(scan_id)
    if not summary or full is None:
        raise HTTPException(status_code=404, detail=f"Scan #{scan_id} not found")
    # The indexed row is authoritative for identity, time, and score.
    merged = dict(full)
    merged["target"] = summary["target"]
    merged["scan_timestamp"] = summary["scan_timestamp"]
    merged["risk_score"] = summary["risk_score"]
    return merged


@router.get("/history/diff", response_model=ScanDiff)
async def diff_history(base: int, head: int):
    """Compare two scans of the same target: new, resolved, and persisting findings."""
    if base == head:
        raise HTTPException(status_code=400, detail="Choose two different scans to compare")

    from assessment.scan_diff import diff_scans

    with _db() as db:
        base_scan = _load_for_diff(db, base)
        head_scan = _load_for_diff(db, head)

    if base_scan["target"] != head_scan["target"]:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scans target different devices ({base_scan['target']} vs "
                f"{head_scan['target']}); diff compares scans of the same target"
            ),
        )

    return diff_scans(base_scan, head_scan, base_id=base, head_id=head)


@router.get("/history/{scan_id}")
async def get_scan(scan_id: int):
    try:
        with _db() as db:
            scan = db.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/history/{scan_id}", response_model=ScanHistoryEntry)
async def update_scan_annotations(scan_id: int, update: ScanAnnotationUpdate):
    """Set tags and/or notes on a stored scan."""
    with _db() as db:
        if not db.update_annotations(scan_id, tags=update.tags, notes=update.notes):
            raise HTTPException(status_code=404, detail="Scan not found")
        summary = db.get_scan_summary(scan_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _entry(summary)


@router.delete("/history/{scan_id}")
async def delete_scan(scan_id: int):
    try:
        with _db() as db:
            deleted = db.delete_scan(scan_id)
        if deleted:
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Scan not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
