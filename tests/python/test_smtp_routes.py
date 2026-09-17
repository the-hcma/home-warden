"""Tests for app.api.smtp_routes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.smtp_config import SmtpConfig, SmtpConfigUpdate, load_smtp_config, save_smtp_config
from app.smtp_service import SmtpDeliveryResult


def _allow_all(username: str, password: str) -> bool:
    return True


def _update(**overrides) -> SmtpConfigUpdate:
    defaults = {
        "from_address": "alerts@example.com",
        "host": "smtp.example.com",
        "mail_domain": "example.com",
        "password": "s3cret",
        "port": 587,
        "username": "alerts",
    }
    defaults.update(overrides)
    return SmtpConfigUpdate(**defaults)


def make_client() -> TestClient:
    client = TestClient(
        create_app(authenticate_user=_allow_all, session_secret="test-session-secret"),
        base_url="https://testserver",
    )
    login = client.post("/auth/login", json={"username": "tester", "password": "irrelevant"})
    assert login.status_code == 200
    return client


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("delete", "/settings/smtp", None),
        ("get", "/settings/smtp", None),
        ("put", "/settings/smtp", _update().__dict__),
        (
            "post",
            "/settings/smtp/test",
            {**_update().__dict__, "to_address": "ops@example.com"},
        ),
    ],
)
def test_smtp_routes_require_session(method: str, path: str, payload: dict | None) -> None:
    client = TestClient(create_app(session_secret="test-session-secret"), base_url="https://testserver")
    request = getattr(client, method)
    response = request(path, json=payload) if payload is not None else request(path)
    assert response.status_code == 401


def test_get_smtp_settings_returns_null_when_unset(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml") as config_path_mock,
    ):
        response = client.get("/settings/smtp")
    assert response.status_code == 200
    assert response.json() is None
    config_path_mock.assert_called()


def test_get_smtp_settings_host_guard_refused() -> None:
    client = make_client()
    with patch("app.api.smtp_routes.enforce_host_guard", return_value=False):
        response = client.get("/settings/smtp")
    assert response.status_code == 503


def test_put_smtp_settings_saves_and_omits_password(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["password_configured"] is True
    assert "password" not in body


def test_put_smtp_settings_rejects_empty_host(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
            },
        )
    assert response.status_code == 422


def test_put_smtp_settings_rejects_out_of_range_port(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 70000,
                "username": "alerts",
            },
        )
    assert response.status_code == 422


def test_put_smtp_settings_keeps_password_when_connection_target_unchanged(tmp_path: Path) -> None:
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="original-secret"), config_path)
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",  # same host/port/username as stored
                "mail_domain": "changed.example.com",
                "password": None,  # blank -- "keep current"
                "port": 587,
                "username": "alerts",
            },
        )
    assert response.status_code == 200
    assert response.json()["password_configured"] is True
    reloaded = load_smtp_config(config_path)
    assert reloaded is not None
    assert reloaded.password == "original-secret"


def test_put_smtp_settings_clears_password_when_host_changes(tmp_path: Path) -> None:
    # Regression: a blank password field means "keep current" only for the
    # relay it was issued for -- switching to a different host must not
    # silently carry the old relay's secret over to the new one.
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="original-secret"), config_path)
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "different.example.com",
                "mail_domain": "example.com",
                "password": None,
                "port": 587,
                "username": "alerts",
            },
        )
    assert response.status_code == 200
    assert response.json()["password_configured"] is False
    reloaded = load_smtp_config(config_path)
    assert reloaded is not None
    assert reloaded.password == ""


def test_put_smtp_settings_clears_password_when_port_changes(tmp_path: Path) -> None:
    # Regression: the reuse guard originally compared host only, so
    # keeping the host but switching the port still got handed the old
    # port's stored secret.
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="original-secret", port=587), config_path)
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": None,
                "port": 2525,
                "username": "alerts",
            },
        )
    assert response.status_code == 200
    assert response.json()["password_configured"] is False


def test_put_smtp_settings_storage_error_returns_409(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("fqdn = warden.example.com\n")  # unquoted string -- invalid TOML
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
            },
        )
    assert response.status_code == 409
    # The malformed file must be left untouched, not silently overwritten.
    assert config_path.read_text() == "fqdn = warden.example.com\n"


def test_delete_smtp_settings_storage_error_returns_409(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("fqdn = warden.example.com\n")
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.delete("/settings/smtp")
    assert response.status_code == 409
    assert config_path.read_text() == "fqdn = warden.example.com\n"


def test_delete_smtp_settings_removes_config(tmp_path: Path) -> None:
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(), config_path)
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
    ):
        response = client.delete("/settings/smtp")
        get_response = client.get("/settings/smtp")
    assert response.status_code == 204
    assert get_response.json() is None


def test_post_smtp_test_email_success(tmp_path: Path) -> None:
    client = make_client()
    fake_result = SmtpDeliveryResult(
        host="smtp.example.com", port=587, recipients=("ops@example.com",), smtp_code=250, smtp_response="OK"
    )
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
        patch("app.api.smtp_routes.send_email", return_value=fake_result) as send_mock,
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
                "to_address": "ops@example.com",
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert "ops@example.com" in body["message"]
    send_mock.assert_called_once()


def test_post_smtp_test_email_translates_failure(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
        patch("app.api.smtp_routes.send_email", side_effect=ConnectionRefusedError("refused")),
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
                "to_address": "ops@example.com",
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "was refused" in body["message"]


def test_post_smtp_test_email_rejects_empty_recipient(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
                "to_address": "",
            },
        )
    assert response.status_code == 422


def test_post_smtp_test_email_reuses_stored_password_for_same_host(tmp_path: Path) -> None:
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="stored-secret"), config_path)
    captured_params = []

    def _capture(params, message):
        captured_params.append(params)
        return SmtpDeliveryResult(
            host=params.host, port=params.port, recipients=("ops@example.com",), smtp_code=250, smtp_response="OK"
        )

    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
        patch("app.api.smtp_routes.send_email", side_effect=_capture),
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",  # same host as stored
                "mail_domain": "example.com",
                "password": None,  # blank draft -- should reuse stored secret
                "port": 587,
                "username": "alerts",
                "to_address": "ops@example.com",
            },
        )
    assert response.status_code == 200
    assert captured_params[0].password == "stored-secret"


def test_post_smtp_test_email_does_not_reuse_password_for_different_host(tmp_path: Path) -> None:
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="stored-secret", host="original.example.com"), config_path)
    captured_params = []

    def _capture(params, message):
        captured_params.append(params)
        return SmtpDeliveryResult(
            host=params.host, port=params.port, recipients=("ops@example.com",), smtp_code=250, smtp_response="OK"
        )

    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
        patch("app.api.smtp_routes.send_email", side_effect=_capture),
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "different.example.com",
                "mail_domain": "example.com",
                "password": None,
                "port": 587,
                "username": "alerts",
                "to_address": "ops@example.com",
            },
        )
    assert response.status_code == 200
    assert captured_params[0].password == ""


def test_post_smtp_test_email_does_not_reuse_password_for_different_port(tmp_path: Path) -> None:
    # Regression: the reuse guard originally compared host only, so a
    # draft keeping the stored host but switching only the port still got
    # handed the stored password -- letting any session pivot the
    # operator's saved credential onto an arbitrary host:port of its
    # choosing (host stays "trusted", port doesn't).
    client = make_client()
    config_path = tmp_path / "config.toml"
    save_smtp_config(_update(password="stored-secret", host="smtp.example.com", port=587), config_path)
    captured_params = []

    def _capture(params, message):
        captured_params.append(params)
        return SmtpDeliveryResult(
            host=params.host, port=params.port, recipients=("ops@example.com",), smtp_code=250, smtp_response="OK"
        )

    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=config_path),
        patch("app.api.smtp_routes.send_email", side_effect=_capture),
    ):
        response = client.post(
            "/settings/smtp/test",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",  # same host as stored
                "mail_domain": "example.com",
                "password": None,
                "port": 2525,  # different port
                "username": "alerts",
                "to_address": "ops@example.com",
            },
        )
    assert response.status_code == 200
    assert captured_params[0].password == ""


def test_smtp_config_round_trips_through_route(tmp_path: Path) -> None:
    client = make_client()
    with (
        patch("app.api.smtp_routes.enforce_host_guard", return_value=True),
        patch("app.smtp_config.config_path", return_value=tmp_path / "config.toml"),
    ):
        client.put(
            "/settings/smtp",
            json={
                "from_address": "alerts@example.com",
                "host": "smtp.example.com",
                "mail_domain": "example.com",
                "password": "s3cret",
                "port": 587,
                "username": "alerts",
            },
        )
        response = client.get("/settings/smtp")
    assert response.status_code == 200
    body = response.json()
    assert body["host"] == "smtp.example.com"
    assert body["password_configured"] is True


def test_smtp_config_dataclass_used_directly() -> None:
    # Sanity: the dataclass this module re-exports for internal reuse is
    # still importable from app.smtp_config as smtp_config's own tests expect.
    config = SmtpConfig(host="a")
    assert config.host == "a"
