"""Health check route."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from config.settings import get_settings

router = APIRouter()


@router.get("", summary="Health check")
async def health() -> JSONResponse:
    s = get_settings()
    return JSONResponse({"status": "ok", "env": s.app_env, "version": "1.0.0"})
