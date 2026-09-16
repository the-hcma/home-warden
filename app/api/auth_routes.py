"""Session login/logout routes for the home-warden web UI (#68)."""

from __future__ import annotations

import math
from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

from app.home_warden_auth import get_session_username, require_session
from app.login_rate_limit import LoginRateLimiter

STATIC_DIR = Path(__file__).resolve().parent / "static"


class LoginRequest(BaseModel):
    password: str
    username: str


router = APIRouter(tags=["auth"])


@router.get("/auth/session")
def get_session(username: str = Depends(require_session)) -> dict[str, str | bool]:
    return {"authenticated": True, "username": username}


@router.get("/login", response_model=None)
def login_page(request: Request) -> FileResponse | RedirectResponse:
    if get_session_username(request) is not None:
        return RedirectResponse(url="/", status_code=HTTPStatus.SEE_OTHER)
    return FileResponse(STATIC_DIR / "index.html")


@router.post("/auth/login")
def login(request: Request, payload: LoginRequest) -> dict[str, str | bool]:
    limiter = _rate_limiter(request)
    client_key = _client_key(request)
    wait_seconds = limiter.seconds_until_allowed(client_key)
    if wait_seconds > 0:
        retry_after = str(math.ceil(wait_seconds))
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="too many failed login attempts; try again shortly",
            headers={"Retry-After": retry_after},
        )
    auth_backend = _auth_backend(request)
    try:
        authenticated = auth_backend(payload.username, payload.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if not authenticated:
        limiter.record_failure(client_key)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid username or password")
    limiter.record_success(client_key)
    request.session.clear()
    request.session["username"] = payload.username
    return {"authenticated": True, "username": payload.username}


@router.post("/auth/logout", status_code=HTTPStatus.NO_CONTENT)
def logout(request: Request) -> Response:
    request.session.clear()
    return Response(status_code=HTTPStatus.NO_CONTENT)


def _auth_backend(request: Request) -> Callable[[str, str], bool]:
    return request.app.state.authenticate_user


def _rate_limiter(request: Request) -> LoginRateLimiter:
    return request.app.state.login_rate_limiter


def _client_key(request: Request) -> str:
    # Keyed by source IP, not username -- see app/login_rate_limit.py for
    # why (an attacker must not be able to lock a legitimate operator out
    # of their own username by spraying guesses from elsewhere). request
    # .client is only None in unusual ASGI setups (e.g. some test
    # transports); fall back to a single shared bucket rather than skip
    # throttling entirely in that case.
    return request.client.host if request.client is not None else "unknown"
