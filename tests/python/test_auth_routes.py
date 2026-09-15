"""Tests for the PAM-backed auth flow."""

from __future__ import annotations

from http import HTTPStatus

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.home_warden_auth import SESSION_COOKIE_NAME


def _allow_only_alice(username: str, password: str) -> bool:
    return (username, password) == ("alice", "correct horse battery staple")


def make_client() -> TestClient:
    return TestClient(
        create_app(authenticate_user=_allow_only_alice, session_secret="test-session-secret"),
        base_url="https://testserver",
    )


def test_failed_login_returns_401_without_cookie() -> None:
    client = make_client()
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert SESSION_COOKIE_NAME not in resp.cookies
    assert "set-cookie" not in resp.headers


def test_logout_invalidates_session() -> None:
    client = make_client()
    login = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert login.status_code == HTTPStatus.OK

    logout = client.post("/auth/logout")
    assert logout.status_code == HTTPStatus.NO_CONTENT

    session = client.get("/auth/session")
    assert session.status_code == HTTPStatus.UNAUTHORIZED


def test_protected_route_requires_session_cookie() -> None:
    client = make_client()
    resp = client.get("/auth/session")
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_protected_route_succeeds_with_valid_session_cookie() -> None:
    client = make_client()
    login = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert login.status_code == HTTPStatus.OK

    session_cookie = login.headers["set-cookie"].lower()
    assert f"{SESSION_COOKIE_NAME}=" in session_cookie
    assert "httponly" in session_cookie
    assert "samesite=strict" in session_cookie
    assert "secure" in session_cookie
    assert "max-age=14400" in session_cookie

    session = client.get("/auth/session")
    assert session.status_code == HTTPStatus.OK
    assert session.json() == {"authenticated": True, "username": "alice"}


def test_login_backend_runtime_error_returns_503() -> None:
    def _unavailable(username: str, password: str) -> bool:
        raise RuntimeError("python-pam is unavailable")

    client = TestClient(
        create_app(authenticate_user=_unavailable, session_secret="test-session-secret"),
        base_url="https://testserver",
    )
    resp = client.post("/auth/login", json={"username": "alice", "password": "irrelevant"})
    assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE


def test_successful_login_sets_session_cookie() -> None:
    client = make_client()
    resp = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == {"authenticated": True, "username": "alice"}
    assert SESSION_COOKIE_NAME in resp.cookies
