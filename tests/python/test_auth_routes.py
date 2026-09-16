"""Tests for the PAM-backed auth flow."""

from __future__ import annotations

from http import HTTPStatus

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.home_warden_auth import SESSION_COOKIE_NAME
from app.login_rate_limit import LoginRateLimiter


def _allow_only_alice(username: str, password: str) -> bool:
    return (username, password) == ("alice", "correct horse battery staple")


def make_client(*, login_rate_limiter: LoginRateLimiter | None = None) -> TestClient:
    return TestClient(
        create_app(
            authenticate_user=_allow_only_alice,
            login_rate_limiter=login_rate_limiter,
            session_secret="test-session-secret",
        ),
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


def test_repeated_failed_logins_are_throttled_with_429() -> None:
    fake_clock = _FakeClock()
    client = make_client(login_rate_limiter=LoginRateLimiter(clock=fake_clock))

    for _ in range(5):
        resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == HTTPStatus.UNAUTHORIZED

    # The 6th failure crosses the default threshold (5): it's still
    # rejected as an auth failure, but the *next* attempt is throttled
    # before the auth backend is even consulted.
    sixth = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert sixth.status_code == HTTPStatus.UNAUTHORIZED

    throttled = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert "retry-after" in throttled.headers


def test_throttle_clears_after_backoff_elapses() -> None:
    fake_clock = _FakeClock()
    client = make_client(login_rate_limiter=LoginRateLimiter(clock=fake_clock))

    for _ in range(6):
        client.post("/auth/login", json={"username": "alice", "password": "wrong"})

    throttled = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS

    fake_clock.advance(2.0)  # base backoff is 1s for the first over-threshold failure
    resp = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert resp.status_code == HTTPStatus.OK


def test_successful_login_resets_the_failure_count() -> None:
    fake_clock = _FakeClock()
    client = make_client(login_rate_limiter=LoginRateLimiter(clock=fake_clock))

    for _ in range(4):
        client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    ok = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert ok.status_code == HTTPStatus.OK

    client.post("/auth/logout")
    for _ in range(4):
        resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == HTTPStatus.UNAUTHORIZED

    still_allowed = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert still_allowed.status_code == HTTPStatus.OK


class _FakeClock:
    """Deterministic stand-in for time.monotonic so backoff tests don't
    need to sleep for real."""

    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds
