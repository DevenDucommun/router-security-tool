import asyncio

from fastapi import APIRouter, HTTPException

from api.schemas import FilesystemRequest, FilesystemResult

router = APIRouter()


def _explore_filesystem(host: str, port: int, username: str, password: str):
    from connections.manager import ConnectionManager
    from scraper.filesystem import FileSystemScraper

    conn = ConnectionManager()
    success = conn.connect_ssh(host, username, password, port=port)
    if not success:
        raise ConnectionError(f"SSH connection to {host}:{port} failed")

    try:
        scraper = FileSystemScraper(conn)
        results = scraper.explore_filesystem()
    finally:
        conn.disconnect()

    return results


@router.post("/filesystem", response_model=FilesystemResult)
async def explore_filesystem(request: FilesystemRequest):
    import os
    password = request.password or os.environ.get("ROUTER_PASS", "")
    if not password:
        raise HTTPException(status_code=400, detail="Password required")

    try:
        results = await asyncio.to_thread(
            _explore_filesystem, request.host, request.port, request.username, password
        )
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Filesystem exploration failed: {e}")

    return FilesystemResult(
        file_structure=results.get("file_structure", {}),
        interesting_files=results.get("interesting_files", []),
        security_findings=results.get("security_findings", []),
    )
