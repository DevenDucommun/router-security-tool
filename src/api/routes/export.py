import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()


def _get_db():
    from database.scan_history import ScanHistoryDB
    return ScanHistoryDB()


@router.post("/export/{format}")
async def export_scan(format: str, scan_id: int = None):
    if format not in ("json", "html", "pdf"):
        raise HTTPException(status_code=400, detail="Format must be json, html, or pdf")

    db = _get_db()

    if scan_id:
        scan_results = db.get_scan_by_id(scan_id)
        if not scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        scans = db.get_all_scans(limit=1)
        if not scans:
            raise HTTPException(status_code=404, detail="No scans available")
        scan_results = db.get_scan_by_id(scans[0]["id"])

    from reports.export import ReportExporter
    exporter = ReportExporter()

    suffix = f".{format}"
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    tmp_path = tmp.name
    tmp.close()

    if format == "json":
        success = exporter.export_to_json(scan_results, tmp_path)
    elif format == "html":
        success = exporter.export_to_html(scan_results, tmp_path)
    else:
        success = exporter.export_to_pdf(scan_results, tmp_path)

    if not success:
        raise HTTPException(status_code=500, detail="Export failed")

    media_types = {"json": "application/json", "html": "text/html", "pdf": "application/pdf"}
    target = scan_results.get("target", "scan")
    filename = f"security_report_{target}.{format}"

    return FileResponse(
        path=tmp_path,
        media_type=media_types[format],
        filename=filename,
    )
