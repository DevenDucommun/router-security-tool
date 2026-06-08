from fastapi import APIRouter, HTTPException

from api.schemas import ScanHistoryEntry, HistoryStats

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
