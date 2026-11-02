from fastapi import APIRouter, HTTPException

from api.schemas import ScanHistoryEntry, HistoryStats, ScanDiff

router = APIRouter()


def _get_db():
    from database.scan_history import ScanHistoryDB
    return ScanHistoryDB()


@router.get("/history", response_model=list[ScanHistoryEntry])
async def get_history(limit: int = 50, target: str = None, risk_level: str = None):
    try:
        db = _get_db()
        scans = db.get_all_scans(limit=limit)

        if target:
            scans = [s for s in scans if s["target"] == target]
        if risk_level:
            scans = [s for s in scans if s["risk_level"] == risk_level]

        return [
            ScanHistoryEntry(
                id=s["id"],
                target=s["target"],
                scan_timestamp=s["scan_timestamp"],
                risk_score=s["risk_score"],
                vulnerability_count=s["vulnerability_count"],
                risk_level=s["risk_level"],
                device_vendor=s.get("device_vendor", ""),
                device_model=s.get("device_model", ""),
            )
            for s in scans
        ]
    except Exception:
        return []


@router.get("/history/stats", response_model=HistoryStats)
async def get_history_stats():
    try:
        db = _get_db()
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

    db = _get_db()
    try:
        base_scan = _load_for_diff(db, base)
        head_scan = _load_for_diff(db, head)
    finally:
        db.close()

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
        db = _get_db()
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/history/{scan_id}")
async def delete_scan(scan_id: int):
    try:
        db = _get_db()
        if db.delete_scan(scan_id):
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Scan not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
