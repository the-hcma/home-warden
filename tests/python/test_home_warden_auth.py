"""Tests for app.home_warden_auth (#68) -- PAM auth + session-secret helpers.

Covers the pieces app.api.auth_routes/app.py rely on but don't exercise
directly: the session-secret file's persistence/permissions contract,
authenticate_with_pam's short-circuit on empty credentials, get_session_username's
type/emptiness guard, and _pam_authenticator's ImportError -> RuntimeError
mapping (the thing that turns a missing python-pam into a clean 503 instead
of an unhandled crash).
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from starlette.requests import Request

from app.home_warden_auth import (
    _pam_authenticator,
    authenticate_with_pam,
    ensure_session_secret,
    get_session_username,
)


def _request_with_session(session: dict) -> Request:
    request = Request({"type": "http", "headers": []})
    request.scope["session"] = session
    return request


def test_ensure_session_secret_persists_across_calls(tmp_path: Path) -> None:
    secret_path = tmp_path / "session-secret"
    first = ensure_session_secret(secret_path)
    second = ensure_session_secret(secret_path)
    assert first == second
    assert first  # non-empty


def test_ensure_session_secret_file_is_owner_only(tmp_path: Path) -> None:
    secret_path = tmp_path / "nested" / "session-secret"
    ensure_session_secret(secret_path)
    mode = stat.S_IMODE(secret_path.stat().st_mode)
    assert mode == 0o600


def test_authenticate_with_pam_rejects_empty_username_without_calling_pam(monkeypatch) -> None:
    called = False

    def _boom() -> None:
        nonlocal called
        called = True
        raise AssertionError("must not reach PAM for an empty username")

    monkeypatch.setattr("app.home_warden_auth._pam_authenticator", _boom)
    assert authenticate_with_pam("", "some-password") is False
    assert called is False


def test_authenticate_with_pam_rejects_empty_password_without_calling_pam(monkeypatch) -> None:
    called = False

    def _boom() -> None:
        nonlocal called
        called = True
        raise AssertionError("must not reach PAM for an empty password")

    monkeypatch.setattr("app.home_warden_auth._pam_authenticator", _boom)
    assert authenticate_with_pam("alice", "") is False
    assert called is False


def test_authenticate_with_pam_delegates_to_pam_client(monkeypatch) -> None:
    fake_client = MagicMock()
    fake_client.authenticate.return_value = True
    monkeypatch.setattr("app.home_warden_auth._pam_authenticator", lambda: fake_client)

    assert authenticate_with_pam("alice", "hunter2") is True
    fake_client.authenticate.assert_called_once_with("alice", "hunter2", service="login")


def test_pam_authenticator_raises_runtime_error_when_python_pam_missing(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "pam", None)
    with pytest.raises(RuntimeError):
        _pam_authenticator()


def test_get_session_username_returns_none_when_absent() -> None:
    request = _request_with_session({})
    assert get_session_username(request) is None


def test_get_session_username_returns_none_for_empty_string() -> None:
    request = _request_with_session({"username": ""})
    assert get_session_username(request) is None


def test_get_session_username_returns_none_for_non_string() -> None:
    request = _request_with_session({"username": 123})
    assert get_session_username(request) is None


def test_get_session_username_returns_the_username() -> None:
    request = _request_with_session({"username": "alice"})
    assert get_session_username(request) == "alice"
