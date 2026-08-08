"""Modeem AI Platform — API entrypoint."""

from app.core.paths import ensure_shared_packages_importable

ensure_shared_packages_importable()

from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.connections import router as connections_router
from app.api.v1 import router as v1_router
from app.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.app_version)
    app.include_router(v1_router)
    app.include_router(auth_router)
    app.include_router(connections_router)
    return app


app = create_app()
