"""Tests for the PAM-backed auth flow."""

from __future__ import annotations

from http import HTTPStatus

from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api.app import create_app
from app.home_warden_auth import SESSION_COOKIE_NAME
from app.login_rate_limit import LoginRateLimiter


def _allow_only_alice(username: str, password: str) -> bool:
    return (username, password) == ("alice", "correct horse battery staple")


def make_client(
    *,
    client_peer: tuple[str, int] = ("testclient", 50000),
    login_rate_limiter: LoginRateLimiter | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            authenticate_user=_allow_only_alice,
            login_rate_limiter=login_rate_limiter,
            session_secret="test-session-secret",
        ),
        base_url="https://testserver",
        client=client_peer,
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


def _make_proxied_client(
    *,
    client_peer: tuple[str, int],
    login_rate_limiter: LoginRateLimiter,
    trusted_hosts: str = "127.0.0.1",
) -> TestClient:
    # Mirrors config/serve.py's real wiring (uvicorn.run(..., proxy_headers=
    # True, forwarded_allow_ips=BACKEND_LOOPBACK_HOST)): create_app() alone
    # never sees X-Forwarded-For, since that rewriting is uvicorn's own
    # ProxyHeadersMiddleware, applied outside the ASGI app itself.
    inner_app = create_app(
        authenticate_user=_allow_only_alice,
        login_rate_limiter=login_rate_limiter,
        session_secret="test-session-secret",
    )
    # uvicorn's and Starlette's ASGI protocol types are structurally
    # identical (both implement the same ASGI spec) but nominally
    # distinct, so pyright rejects passing a Starlette app into uvicorn's
    # ProxyHeadersMiddleware, and that middleware back into Starlette's
    # TestClient -- runtime behavior is unaffected either way.
    app = ProxyHeadersMiddleware(inner_app, trusted_hosts=trusted_hosts)  # type: ignore[arg-type]
    return TestClient(app, base_url="https://testserver", client=client_peer)  # type: ignore[arg-type]


def test_forwarded_header_from_trusted_peer_keys_the_real_client() -> None:
    # home-warden#82: nginx (the loopback peer) sets X-Forwarded-For to the
    # real visitor address. Two distinct forwarded addresses arriving from
    # that one trusted peer must be throttled independently -- proving the
    # limiter is keying on the forwarded address, not nginx's own peer
    # address (which would collapse both into one shared bucket).
    shared_limiter = LoginRateLimiter(clock=_FakeClock())
    attacker = _make_proxied_client(
        client_peer=("127.0.0.1", 50000),
        login_rate_limiter=shared_limiter,
    )
    attacker.headers["X-Forwarded-For"] = "10.0.0.9"
    victim = _make_proxied_client(
        client_peer=("127.0.0.1", 50001),
        login_rate_limiter=shared_limiter,
    )
    victim.headers["X-Forwarded-For"] = "10.0.0.10"

    for _ in range(6):
        attacker.post("/auth/login", json={"username": "alice", "password": "wrong"})
    throttled = attacker.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS

    still_ok = victim.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert still_ok.status_code == HTTPStatus.OK


def test_forwarded_header_from_untrusted_peer_is_ignored() -> None:
    # A non-nginx peer forging X-Forwarded-For must not be able to spread
    # its failures across fake identities to dodge the limiter, nor pin
    # them onto a victim's real address -- ProxyHeadersMiddleware only
    # rewrites the client for a peer in trusted_hosts, so an untrusted
    # peer's header is dropped entirely and every request still keys on
    # its own real (untrusted) peer address.
    limiter = LoginRateLimiter(clock=_FakeClock())
    client = _make_proxied_client(
        client_peer=("10.0.0.1", 50000),
        login_rate_limiter=limiter,
    )

    for i in range(6):
        client.headers["X-Forwarded-For"] = f"1.2.3.{i}"  # a different forged identity every request
        client.post("/auth/login", json={"username": "alice", "password": "wrong"})

    client.headers["X-Forwarded-For"] = "9.9.9.9"
    throttled = client.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_a_different_source_ip_is_unaffected_while_one_is_throttled() -> None:
    # Pins the module's core claim (per-IP, not global/per-username): two
    # clients sharing one LoginRateLimiter instance but distinct peer
    # addresses must not affect each other. Without this, swapping
    # _client_key to key on username (or a constant) would still pass
    # every other throttling test in this file, since they all use one
    # username *and* one peer address.
    shared_limiter = LoginRateLimiter(clock=_FakeClock())
    attacker = make_client(client_peer=("10.0.0.1", 50000), login_rate_limiter=shared_limiter)
    victim = make_client(client_peer=("10.0.0.2", 50000), login_rate_limiter=shared_limiter)

    for _ in range(6):
        attacker.post("/auth/login", json={"username": "alice", "password": "wrong"})
    throttled = attacker.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert throttled.status_code == HTTPStatus.TOO_MANY_REQUESTS

    still_ok = victim.post("/auth/login", json={"username": "alice", "password": "correct horse battery staple"})
    assert still_ok.status_code == HTTPStatus.OK


class _FakeClock:
    """Deterministic stand-in for time.monotonic so backoff tests don't
    need to sleep for real."""

    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds
