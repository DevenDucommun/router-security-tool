import asyncio

from fastapi import APIRouter

from api.schemas import DeviceDiscovery, DiscoveredDevice

router = APIRouter()


def _discover_devices():
    from connections.detector import ConnectionDetector
    detector = ConnectionDetector()
    return detector.get_all_connections()


@router.get("/devices", response_model=DeviceDiscovery)
async def discover_devices():
    connections = await asyncio.to_thread(_discover_devices)

    devices = [
        DiscoveredDevice(
            ip=c.get("ip", ""),
            port=c.get("port", 22),
            type=c.get("type", "network"),
            description=c.get("description", ""),
            device=c.get("device", ""),
            likely_router=c.get("likely_router", False),
        )
        for c in connections
    ]

    return DeviceDiscovery(devices=devices)
