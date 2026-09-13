"""FastAPI ASGI app: home-warden's HTTP API.

Currently just catalog health (the-hcma/home-warden#57); the future web UI
(#55) is expected to grow this app with more routes rather than start a
second one.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.catalog_health_routes import router as catalog_health_router


def create_app() -> FastAPI:
    app = FastAPI(title="home-warden", version="0.1.0")
    app.include_router(catalog_health_router)
    return app
