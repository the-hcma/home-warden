"""Session login/logout routes for the home-warden web UI (#68)."""

from __future__ import annotations

from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

from app.home_warden_auth import get_session_username

STATIC_DIR = Path(__file__).resolve().parent / "static"


class LoginRequest(BaseModel):
    password: str
    username: str


router = APIRouter(tags=["auth"])


@router.get("/auth/session")
def get_session(request: Request) -> dict[str, str | bool]:
    username = get_session_username(request)
    if username is None:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="authentication required")
    return {"authenticated": True, "username": username}


@router.get("/login", response_model=None)
def login_page(request: Request) -> FileResponse | RedirectResponse:
    if get_session_username(request) is not None:
        return RedirectResponse(url="/", status_code=HTTPStatus.SEE_OTHER)
    return FileResponse(STATIC_DIR / "index.html")


@router.post("/auth/login")
def login(request: Request, payload: LoginRequest) -> dict[str, str | bool]:
    auth_backend = _auth_backend(request)
    try:
        authenticated = auth_backend(payload.username, payload.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if not authenticated:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="invalid username or password")
    request.session.clear()
    request.session["username"] = payload.username
    return {"authenticated": True, "username": payload.username}


@router.post("/auth/logout", status_code=HTTPStatus.NO_CONTENT)
def logout(request: Request) -> Response:
    request.session.clear()
    return Response(status_code=HTTPStatus.NO_CONTENT)


def _auth_backend(request: Request) -> Callable[[str, str], bool]:
    return request.app.state.authenticate_user
