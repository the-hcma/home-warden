"""PAM-backed session auth helpers for the home-warden web UI (#68)."""

from __future__ import annotations

import os
import secrets
from http import HTTPStatus
from pathlib import Path

from fastapi import HTTPException
from starlette.requests import Request

from app.home_warden_config import config_path

PAM_SERVICE = "login"
SESSION_COOKIE_NAME = "home_warden_session"
SESSION_SECRET_FILENAME = "session-secret"
SESSION_TTL_SECONDS = 4 * 60 * 60


def authenticate_with_pam(username: str, password: str) -> bool:
    if not username or not password:
        return False
    client = _pam_authenticator()
    return bool(client.authenticate(username, password, service=PAM_SERVICE))


def ensure_session_secret(path: Path | None = None) -> str:
    resolved_path = session_secret_path(path)
    try:
        secret = resolved_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        secret = ""
    except OSError:
        secret = ""
    if secret:
        return secret

    secret = secrets.token_urlsafe(48)
    try:
        resolved_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # O_EXCL + mode=0o600 on open (not write-then-chmod) so the key is
        # never briefly world-readable under the process umask, and so a
        # concurrent writer loses the race cleanly (FileExistsError) instead
        # of silently truncating the other's secret.
        fd = os.open(resolved_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, f"{secret}\n".encode("utf-8"))
        finally:
            os.close(fd)
    except FileExistsError:
        # Another process won the race and already wrote a secret -- use it
        # rather than keep our own, so every process signs with the same key.
        try:
            return resolved_path.read_text(encoding="utf-8").strip() or secret
        except OSError:
            return secret
    except OSError:
        return secret
    return secret


def get_session_username(request: Request) -> str | None:
    username = request.session.get("username")
    if isinstance(username, str) and username:
        return username
    return None


def require_session(request: Request) -> str:
    """FastAPI dependency: 401s any route that isn't `/`/`/login` unless a
    valid session cookie is present. Needed because #68's self-catalog vhost
    (build_web_ui_catalog_service) proxies *every* path on the configured
    FQDN to this app -- without this, routes like /health/catalog would be
    reachable by anyone who can resolve that hostname, not just an
    authenticated operator.
    """
    username = get_session_username(request)
    if username is None:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="authentication required")
    return username


def session_secret_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    return config_path().parent / SESSION_SECRET_FILENAME


def _pam_authenticator():
    try:
        import pam
    except ImportError as exc:
        raise RuntimeError("python-pam is unavailable") from exc
    return pam.pam()
