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

import app.home_warden_auth as home_warden_auth
from app.home_warden_auth import (
    _pam_authenticator,
    authenticate_with_pam,
    ensure_session_secret,
    get_session_username,
    session_secret_path,
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


def test_ensure_session_secret_uses_concurrent_winners_file(monkeypatch, tmp_path: Path) -> None:
    """Simulates the FileExistsError race: another process creates the file
    between our read and our os.open call. We must read back *its* secret,
    not silently keep signing with our own in-process one (or every worker
    would sign with a different key)."""
    secret_path = tmp_path / "session-secret"
    winner_secret = "winner-secret-value"

    real_open = home_warden_auth.os.open

    def fake_open(path, flags, mode=0o777):
        # The "winner" writes its own secret to the file the instant our
        # os.open would have created it, then we still raise FileExistsError
        # as os.open itself would if the file already existed.
        Path(path).write_text(f"{winner_secret}\n", encoding="utf-8")
        Path(path).chmod(0o600)
        raise FileExistsError(path)

    monkeypatch.setattr(home_warden_auth.os, "open", fake_open)
    result = ensure_session_secret(secret_path)
    monkeypatch.setattr(home_warden_auth.os, "open", real_open)

    assert result == winner_secret


def test_ensure_session_secret_repairs_empty_leftover_file(tmp_path: Path) -> None:
    """A 0-byte file (e.g. left behind by a process that crashed between
    os.open and os.write) must be treated as missing and repaired, not
    returned as-is or looped on forever."""
    secret_path = tmp_path / "session-secret"
    secret_path.write_text("", encoding="utf-8")

    result = ensure_session_secret(secret_path)

    assert result
    assert secret_path.read_text(encoding="utf-8").strip() == result


def test_ensure_session_secret_falls_back_in_memory_on_unwritable_dir(monkeypatch, tmp_path: Path) -> None:
    """When the config directory can't be created/written to at all
    (OSError other than FileExistsError), ensure_session_secret must still
    return a usable secret instead of raising."""
    secret_path = tmp_path / "nested" / "session-secret"

    def raising_mkdir(*args, **kwargs):
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(Path, "mkdir", raising_mkdir)
    result = ensure_session_secret(secret_path)

    assert result
    assert not secret_path.exists()


def test_session_secret_path_defaults_next_to_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(home_warden_auth, "config_path", lambda: tmp_path / "config.toml")
    assert session_secret_path() == tmp_path / "session-secret"


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
