from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routes import api_router
from api.routes.scan import ws_router as scan_ws_router


def _package_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("router-security-tool")
    except PackageNotFoundError:
        return "0.0.0+source"


APP_VERSION = _package_version()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


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

static_path = Path(__file__).parent.parent.parent / "web" / "dist"
if static_path.exists():
    app.mount("/assets", StaticFiles(directory=str(static_path / "assets")), name="assets")

    @app.get("/{path:path}")
    async def spa_fallback(request: Request, path: str):
        file = static_path / path
        if file.is_file():
            return FileResponse(file)
        return FileResponse(static_path / "index.html")
