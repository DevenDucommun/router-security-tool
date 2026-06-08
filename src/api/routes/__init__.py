from fastapi import APIRouter

from api.routes.scan import rest_router as scan_rest_router
from api.routes.scan import ws_router as scan_ws_router
from api.routes.devices import router as devices_router
from api.routes.history import router as history_router
from api.routes.export import router as export_router
from api.routes.filesystem import router as filesystem_router

api_router = APIRouter(prefix="/api")
api_router.include_router(scan_rest_router, tags=["scan"])
api_router.include_router(devices_router, tags=["devices"])
api_router.include_router(history_router, tags=["history"])
api_router.include_router(export_router, tags=["export"])
api_router.include_router(filesystem_router, tags=["filesystem"])
