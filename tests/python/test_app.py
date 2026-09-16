"""Tests for app.api.app's authenticated static-serving scaffold (#67/#68).

Covers only the scaffold's own concerns -- the index/login routes and the
/static/ mount actually serve the committed/built files, gated by session
auth. Route-specific behavior (health, future catalog/auth routes) is
tested alongside those routers.
"""

from __future__ import annotations

from http import HTTPStatus

from fastapi.testclient import TestClient

from app.api.app import STATIC_DIR, create_app


def _allow_all(username: str, password: str) -> bool:
    return True


def make_client() -> TestClient:
    return TestClient(
        create_app(authenticate_user=_allow_all, session_secret="test-session-secret"),
        base_url="https://testserver",
    )


def test_authenticated_root_serves_static_html() -> None:
    client = make_client()
    login = client.post("/auth/login", json={"username": "alice", "password": "ignored"})
    assert login.status_code == HTTPStatus.OK

    resp = client.get("/")
    assert resp.status_code == HTTPStatus.OK
    assert resp.headers["content-type"].startswith("text/html")
    assert '<div id="app">' in resp.text


def test_login_route_serves_static_html_when_logged_out() -> None:
    client = make_client()
    resp = client.get("/login")
    assert resp.status_code == HTTPStatus.OK
    assert resp.headers["content-type"].startswith("text/html")
    assert '<div id="app">' in resp.text


def test_login_route_redirects_to_root_when_already_authenticated() -> None:
    client = make_client()
    client.post("/auth/login", json={"username": "alice", "password": "ignored"})

    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == HTTPStatus.SEE_OTHER
    assert resp.headers["location"] == "/"


def test_root_redirects_to_login_when_logged_out() -> None:
    client = make_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == HTTPStatus.SEE_OTHER
    assert resp.headers["location"] == "/login"


def test_static_dir_is_the_committed_app_api_static_dir() -> None:
    # Guards against accidentally pointing STATIC_DIR somewhere else (e.g. a
    # repo-root static/ or the web/ source tree) as the module is refactored.
    assert STATIC_DIR.name == "static"
    assert STATIC_DIR.parent.name == "api"
    assert (STATIC_DIR / "index.html").is_file()


def test_static_mount_404s_on_missing_dist_file() -> None:
    # dist/ is gitignored (esbuild output) -- a checkout without a `web/`
    # build must not crash the app, just 404 the bundle. check_dir=False on
    # the StaticFiles mount is what makes this the failure mode instead of a
    # startup error.
    client = make_client()
    resp = client.get("/static/dist/does-not-exist.js")
    assert resp.status_code == 404


def test_static_mount_serves_a_committed_file() -> None:
    # A 404 on a missing file (above) passes for *any* directory/prefix the
    # mount happens to point at. Pin the positive case too: index.html is
    # tracked, so this fails loudly if STATIC_DIR or the /static prefix ever
    # drifts from what index.html's <script src> actually expects.
    client = make_client()
    resp = client.get("/static/index.html")
    assert resp.status_code == 200
    assert '<div id="app">' in resp.text

    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert '<script type="module" src="/static/dist/main.js">' in index_html


def test_swagger_and_redoc_are_disabled() -> None:
    # #76: FastAPI's default /docs and /redoc pull JS/CSS from third-party
    # CDNs, which the app's own CSP blocks anyway (a blank page), and this
    # app has no public API contract needing a live schema browser -- both
    # must be off rather than left broken.
    client = make_client()
    assert client.get("/docs").status_code == HTTPStatus.NOT_FOUND
    assert client.get("/redoc").status_code == HTTPStatus.NOT_FOUND


def test_security_headers_present_on_every_response() -> None:
    # #76: baseline hardening headers must be present regardless of route,
    # auth state, or status code -- check an unauthenticated 303 redirect,
    # not just a 200, since header middleware bugs often only show up on
    # early-return responses.
    client = make_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == HTTPStatus.SEE_OTHER
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "same-origin"
    assert "default-src 'self'" in resp.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "max-age=" in resp.headers["strict-transport-security"]
