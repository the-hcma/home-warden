"""Tests for app.api.app's static-serving scaffold (the-hcma/home-warden#67).

Covers only the scaffold's own concerns -- the index route and the /static/
mount actually serve the committed/built files. Route-specific behavior
(health, future catalog/auth routes) is tested alongside those routers.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.app import STATIC_DIR, create_app


def make_client() -> TestClient:
    return TestClient(create_app())


def test_index_serves_static_html() -> None:
    client = make_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert '<div id="app">' in resp.text


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
