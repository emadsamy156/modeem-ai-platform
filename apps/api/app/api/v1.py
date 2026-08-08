"""API v1 routes."""

from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    return {"status": "healthy", "service": settings.service_name}


@router.get("/info")
def info() -> dict[str, str]:
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "api_version": settings.api_version,
    }
