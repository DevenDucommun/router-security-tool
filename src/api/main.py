import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routes import api_router
from api.routes.scan import ws_router as scan_ws_router
from api.routes.batch import ws_router as batch_ws_router


def _package_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("router-security-tool")
    except PackageNotFoundError:
        return "0.0.0+source"


APP_VERSION = _package_version()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from api.scheduler import get_scheduler, scheduler_enabled

    scheduler = get_scheduler() if scheduler_enabled() else None
    if scheduler:
        scheduler.start()
    try:
        yield
    finally:
        if scheduler:
            await scheduler.stop()


app = FastAPI(
    title="Router Security Tool",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


app.include_router(api_router)
app.include_router(scan_ws_router)
app.include_router(batch_ws_router)

# The repo-relative default only works from a source checkout / editable
# install; a pip-installed package (e.g. the Docker image) sets
# ROUTER_SECURITY_WEB_DIST to where the built SPA lives.
static_path = Path(
    os.environ.get("ROUTER_SECURITY_WEB_DIST")
    or Path(__file__).parent.parent.parent / "web" / "dist"
)
if static_path.exists():
    app.mount("/assets", StaticFiles(directory=str(static_path / "assets")), name="assets")

    @app.get("/{path:path}")
    async def spa_fallback(request: Request, path: str):
        file = static_path / path
        if file.is_file():
            return FileResponse(file)
        return FileResponse(static_path / "index.html")
