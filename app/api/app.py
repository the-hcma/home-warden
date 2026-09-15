"""FastAPI ASGI app: home-warden's HTTP API and authenticated web UI.

Catalog health (the-hcma/home-warden#57) plus the first real web-ui auth
plumbing (the-hcma/home-warden#68) live in one FastAPI process. nginx stays
responsible for TLS termination; this app stays loopback-only and marks its
session cookie Secure/HttpOnly/SameSite=Strict so browser traffic still
follows the HTTPS-only deployment story.
"""

from __future__ import annotations

from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api.auth_routes import router as auth_router
from app.api.catalog_crud_routes import router as catalog_crud_router
from app.api.catalog_health_routes import router as catalog_health_router
from app.home_warden_auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    authenticate_with_pam,
    ensure_session_secret,
    get_session_username,
    require_session,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(
    *,
    authenticate_user: Callable[[str, str], bool] | None = None,
    session_secret: str | None = None,
) -> FastAPI:
    app = FastAPI(title="home-warden", version="0.1.0")
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret or ensure_session_secret(),
        https_only=True,
        max_age=SESSION_TTL_SECONDS,
        same_site="strict",
        session_cookie=SESSION_COOKIE_NAME,
    )
    app.state.authenticate_user = authenticate_user or authenticate_with_pam
    app.include_router(auth_router)
    # #68's self-catalog vhost proxies every path on the configured FQDN to
    # this app, so a route that used to only matter on a trusted loopback
    # call (health/cert/DNS details, incl. exception text) must not be
    # reachable by an unauthenticated visitor once that vhost exists.
    app.include_router(catalog_crud_router, dependencies=[Depends(require_session)])
    app.include_router(catalog_health_router, dependencies=[Depends(require_session)])
    # dist/ (esbuild output, web/build.mjs) is gitignored -- StaticFiles is
    # instantiated lazily via a mount so a missing dist/ at import time (e.g.
    # `web/` build never run) doesn't crash app startup, only 404s /static/.
    app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")

    @app.get("/", response_model=None)
    def index(request: Request) -> FileResponse | RedirectResponse:
        if get_session_username(request) is None:
            return RedirectResponse(url="/login", status_code=HTTPStatus.SEE_OTHER)
        # Read index.html fresh from disk each request (not embedded in the
        # app) so local edits show up without restarting uvicorn.
        return FileResponse(STATIC_DIR / "index.html")

    return app
