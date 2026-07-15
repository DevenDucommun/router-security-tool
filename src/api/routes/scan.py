import asyncio
import logging
import os
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException

from api.schemas import ScanRequest, ScanResult, Finding, DeviceInfo

logger = logging.getLogger(__name__)

rest_router = APIRouter()
ws_router = APIRouter()


def _run_ssh_assessment(host: str, port: int, username: str, password: str, progress_callback=None):
    from connections.manager import ConnectionManager
    from assessment.ssh_assessor import SSHAssessor

    conn = ConnectionManager()
    if progress_callback:
        progress_callback("Connecting to device...")

    success = conn.connect_ssh(host, username, password, port=port)
    if not success:
        raise ConnectionError(f"SSH connection to {host}:{port} failed")

    if progress_callback:
        progress_callback("Running security assessment...")

    try:
        assessor = SSHAssessor(conn)
        results = assessor.run_assessment()
    finally:
        conn.disconnect()

    return results


def _build_scan_result(results: dict, host: str, duration: float) -> ScanResult:
    findings = [
        Finding(
            id=f.get("id", ""),
            title=f.get("title", ""),
            severity=f.get("severity", "Info"),
            category=f.get("category", ""),
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            remediation=f.get("remediation", ""),
        )
        for f in results.get("findings", [])
    ]

    device = results.get("device_info", {})

    return ScanResult(
        target=host,
        profile=results.get("profile", "generic"),
        device_info=DeviceInfo(
            hostname=device.get("hostname", ""),
            uname=device.get("uname", ""),
            firmware_version=device.get("firmware_version", ""),
            uptime=device.get("uptime", ""),
            os_release=device.get("os_release", ""),
        ),
        findings=findings,
        severity_summary=results.get("severity_summary", {}),
        risk_score=_calculate_risk_score(findings),
        scan_duration=duration,
    )


def _risk_level(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def _calculate_risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    weights = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.0, "Info": 0.5}
    total = sum(weights.get(f.severity.value, 2.0) for f in findings)
    avg = total / len(findings)
    multiplier = min(len(findings) / 8.0, 1.5)
    return min(avg * multiplier, 10.0)


@rest_router.post("/scan", response_model=ScanResult)
async def run_scan(request: ScanRequest):
    password = request.password or os.environ.get("ROUTER_PASS", "")
    if not password:
        raise HTTPException(status_code=400, detail="Password required (body or ROUTER_PASS env var)")

    start = time.time()
    try:
        results = await asyncio.to_thread(
            _run_ssh_assessment, request.host, request.port, request.username, password
        )
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {e}")

    duration = time.time() - start
    scan_result = _build_scan_result(results, request.host, duration)

    try:
        from database.scan_history import ScanHistoryDB
        with ScanHistoryDB() as db:
            db.save_scan({
                "target": scan_result.target,
                "device_info": {"vendor": scan_result.profile, "product": scan_result.device_info.hostname},
                "risk_score": scan_result.risk_score,
                "risk_level": _risk_level(scan_result.risk_score),
                "vulnerabilities": [f.model_dump(mode="json") for f in scan_result.findings],
            })
    except Exception as e:
        logger.warning("Failed to persist scan history for %s: %s", scan_result.target, e)

    return scan_result


@ws_router.websocket("/ws/scan")
async def scan_websocket(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        host = data.get("host", "")
        port = data.get("port", 22)
        username = data.get("username", "root")
        password = data.get("password") or os.environ.get("ROUTER_PASS", "")

        if not host or not password:
            await ws.send_json({"type": "error", "message": "host and password required"})
            return

        await ws.send_json({"type": "progress", "message": "Connecting..."})

        start = time.time()
        progress_queue: asyncio.Queue = asyncio.Queue()

        def sync_progress(msg):
            progress_queue.put_nowait(msg)

        scan_task = asyncio.create_task(
            asyncio.to_thread(_run_ssh_assessment, host, port, username, password, sync_progress)
        )

        while not scan_task.done():
            try:
                msg = await asyncio.wait_for(progress_queue.get(), timeout=0.5)
                await ws.send_json({"type": "progress", "message": msg})
            except asyncio.TimeoutError:
                continue

        while not progress_queue.empty():
            msg = progress_queue.get_nowait()
            await ws.send_json({"type": "progress", "message": msg})

        try:
            results = scan_task.result()
        except Exception as e:
            await ws.send_json({"type": "error", "message": str(e)})
            return

        duration = time.time() - start
        scan_result = _build_scan_result(results, host, duration)
        await ws.send_json({
            "type": "result",
            "data": scan_result.model_dump(mode="json"),
        })

    except WebSocketDisconnect:
        pass
