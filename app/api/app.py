"""FastAPI ASGI app: home-warden's HTTP API.

Catalog health (the-hcma/home-warden#57) plus the web UI scaffold
(the-hcma/home-warden#67) -- more routes/panels grow this app rather than
starting a second one. Auth (PAM login, nginx-fronted-HTTPS-only) and real
UI panels land in later #55 sub-issues (#68/#69/#70); this scaffold only
proves the static-serving pipeline.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.catalog_health_routes import router as catalog_health_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="home-warden", version="0.1.0")
    app.include_router(catalog_health_router)
    # dist/ (esbuild output, web/build.mjs) is gitignored -- StaticFiles is
    # instantiated lazily via a mount so a missing dist/ at import time (e.g.
    # `web/` build never run) doesn't crash app startup, only 404s /static/.
    app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")

    @app.get("/")
    def index() -> FileResponse:
        # Read index.html fresh from disk each request (not embedded in the
        # app) so local edits show up without restarting uvicorn.
        return FileResponse(STATIC_DIR / "index.html")

    return app
