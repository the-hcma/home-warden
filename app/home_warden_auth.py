"""PAM-backed session auth helpers for the home-warden web UI (#68)."""

from __future__ import annotations

import secrets
from pathlib import Path

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
        resolved_path.write_text(f"{secret}\n", encoding="utf-8")
        resolved_path.chmod(0o600)
    except OSError:
        return secret
    return secret


def get_session_username(request: Request) -> str | None:
    username = request.session.get("username")
    if isinstance(username, str) and username:
        return username
    return None


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
