"""
Multi-device batch scanning.

POST /api/targets/parse  — preview how a target list expands (no scanning)
WS   /ws/batch           — scan many targets in parallel with per-device progress

All targets in one batch share the same SSH credentials (the common fleet
case). Each completed device scan is saved to history exactly like a single
scan, so diff, tags, and trends work per device afterwards.
"""

import asyncio
import logging
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from api.routes import scan as scan_routes
from assessment.targets import MAX_BATCH_TARGETS, TargetParseError, parse_targets

logger = logging.getLogger(__name__)

rest_router = APIRouter()
ws_router = APIRouter()

DEFAULT_CONCURRENCY = 4
MAX_CONCURRENCY = 8


class TargetParseRequest(BaseModel):
    targets: str = Field(max_length=20000)


class TargetParseResult(BaseModel):
    targets: List[str]
    errors: List[str]
    count: int
    max_targets: int = MAX_BATCH_TARGETS


@rest_router.post("/targets/parse", response_model=TargetParseResult)
async def preview_targets(request: TargetParseRequest):
    try:
        parsed = parse_targets(request.targets)
    except TargetParseError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return TargetParseResult(targets=parsed["targets"], errors=parsed["errors"], count=len(parsed["targets"]))


def _clamp_concurrency(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CONCURRENCY
    return max(1, min(MAX_CONCURRENCY, n))


class BatchSummary:
    """Aggregates per-device outcomes into a fleet view."""

    def __init__(self, targets: List[str]):
        self.total = len(targets)
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.finding_devices: Counter = Counter()
        self.finding_meta: Dict[str, Dict[str, str]] = {}

    def add_result(self, host: str, result, scan_id: Optional[int]):
        level = scan_routes._risk_level(result.risk_score)
        self.devices[host] = {
            "status": "done",
            "risk_score": round(result.risk_score, 2),
            "risk_level": level,
            "finding_count": len(result.findings),
            "scan_id": scan_id,
        }
        for finding_id in {f.id for f in result.findings}:
            self.finding_devices[finding_id] += 1
        for f in result.findings:
            self.finding_meta.setdefault(f.id, {"title": f.title, "severity": f.severity.value})

    def add_error(self, host: str, message: str):
        self.devices[host] = {"status": "error", "error": message}

    def to_dict(self) -> Dict[str, Any]:
        done = {h: d for h, d in self.devices.items() if d["status"] == "done"}
        by_level = Counter(d["risk_level"] for d in done.values())
        riskiest = sorted(done.items(), key=lambda kv: kv[1]["risk_score"], reverse=True)
        common = [
            {
                "id": fid,
                "title": self.finding_meta[fid]["title"],
                "severity": self.finding_meta[fid]["severity"],
                "devices": count,
            }
            for fid, count in self.finding_devices.most_common(10)
        ]
        return {
            "total": self.total,
            "succeeded": len(done),
            "failed": sum(1 for d in self.devices.values() if d["status"] == "error"),
            "risk_levels": dict(by_level),
            "highest_risk": [{"target": h, **d} for h, d in riskiest[:5]],
            "common_findings": common,
        }


@ws_router.websocket("/ws/batch")
async def batch_websocket(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        port = int(data.get("port", 22))
        username = data.get("username", "root")
        password = data.get("password") or os.environ.get("ROUTER_PASS", "")
        concurrency = _clamp_concurrency(data.get("concurrency", DEFAULT_CONCURRENCY))

        if not password:
            await ws.send_json({"type": "error", "message": "password required"})
            return
        try:
            parsed = parse_targets(str(data.get("targets", "")))
        except TargetParseError as e:
            await ws.send_json({"type": "error", "message": str(e)})
            return
        if parsed["errors"]:
            await ws.send_json({"type": "error", "message": "; ".join(parsed["errors"])})
            return
        targets = parsed["targets"]
        if not targets:
            await ws.send_json({"type": "error", "message": "no targets given"})
            return

        await ws.send_json({"type": "batch_started", "targets": targets, "concurrency": concurrency})
        await _run_batch(ws, targets, port, username, password, concurrency)
    except WebSocketDisconnect:
        # Device scans already running in worker threads finish and are saved;
        # nothing further is sent.
        pass


async def _run_batch(ws: WebSocket, targets: List[str], port: int, username: str, password: str, concurrency: int):
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    semaphore = asyncio.Semaphore(concurrency)
    summary = BatchSummary(targets)
    batch_start = time.time()

    async def scan_one(host: str):
        async with semaphore:
            await queue.put({"type": "target_started", "target": host})

            def progress(message: str):
                # Called from the worker thread: hand off to the event loop safely.
                loop.call_soon_threadsafe(
                    queue.put_nowait, {"type": "target_progress", "target": host, "message": message}
                )

            start = time.time()
            try:
                results = await asyncio.to_thread(
                    scan_routes._run_ssh_assessment, host, port, username, password, progress
                )
                result = scan_routes._build_scan_result(results, host, time.time() - start)
                scan_id = await asyncio.to_thread(scan_routes._persist_scan, result)
            except Exception as e:  # one device failing must not stop the batch
                summary.add_error(host, str(e))
                await queue.put({"type": "target_error", "target": host, "message": str(e)})
                return
            summary.add_result(host, result, scan_id)
            await queue.put({
                "type": "target_result",
                "target": host,
                "scan_id": scan_id,
                "data": result.model_dump(mode="json"),
            })

    runner = asyncio.gather(*(scan_one(host) for host in targets))

    while not runner.done() or not queue.empty():
        try:
            message = await asyncio.wait_for(queue.get(), timeout=0.25)
        except asyncio.TimeoutError:
            continue
        await ws.send_json(message)

    await runner
    await ws.send_json({
        "type": "batch_complete",
        "summary": summary.to_dict(),
        "duration": round(time.time() - batch_start, 2),
    })
