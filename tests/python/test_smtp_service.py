"""Tests for app.smtp_service."""

from __future__ import annotations

import smtplib
import socket
import ssl
from unittest.mock import MagicMock

import pytest

from app.smtp_service import (
    SmtpConnectionParams,
    SmtpNotEncryptedError,
    build_message,
    send_email,
    smtp_friendly_error,
)


def _params(**overrides) -> SmtpConnectionParams:
    defaults = {
        "from_address": "alerts@example.com",
        "host": "smtp.example.com",
        "mail_domain": "example.com",
        "password": "s3cret",
        "port": 587,
        "username": "alerts",
    }
    defaults.update(overrides)
    return SmtpConnectionParams(**defaults)


def test_build_message_sets_headers_and_body() -> None:
    message = build_message(
        from_address="alerts@example.com",
        subject="hello",
        body="world",
        to_address="ops@example.com",
    )
    assert message["From"] == "alerts@example.com"
    assert message["To"] == "ops@example.com"
    assert message["Subject"] == "hello"
    assert message.get_content().strip() == "world"


def test_send_email_starttls_on_587(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.send_message.return_value = {}
    fake_smtp.smtp_data_code = 250
    fake_smtp.smtp_data_response = "OK"
    fake_smtp.has_extn.return_value = True
    fake_smtp.sock = MagicMock(spec=ssl.SSLSocket)
    smtp_cls = MagicMock(return_value=fake_smtp)
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", smtp_cls)

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    result = send_email(_params(port=587), message)

    fake_smtp.starttls.assert_called_once()
    fake_smtp.login.assert_called_once_with("alerts", "s3cret")
    assert result.smtp_code == 250
    assert result.recipients == ("ops@example.com",)


def test_send_email_attempts_starttls_on_any_advertised_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: TLS used to be gated on a hardcoded (587, 2525) port
    # list, so a relay advertising STARTTLS on any other port (e.g. 25)
    # never got upgraded and credentials went out in the clear.
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.send_message.return_value = {}
    fake_smtp.smtp_data_code = 250
    fake_smtp.smtp_data_response = "OK"
    fake_smtp.has_extn.return_value = True
    fake_smtp.sock = MagicMock(spec=ssl.SSLSocket)
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", MagicMock(return_value=fake_smtp))

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    send_email(_params(port=25), message)

    fake_smtp.has_extn.assert_called_once_with("starttls")
    fake_smtp.starttls.assert_called_once()


def test_send_email_refuses_credentials_over_unencrypted_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.has_extn.return_value = False  # server doesn't offer STARTTLS
    fake_smtp.sock = MagicMock()  # a plain socket, not ssl.SSLSocket
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", MagicMock(return_value=fake_smtp))

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    with pytest.raises(SmtpNotEncryptedError):
        send_email(_params(port=25), message)

    fake_smtp.login.assert_not_called()
    fake_smtp.send_message.assert_not_called()


def test_send_email_uses_ssl_on_465(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.send_message.return_value = {}
    fake_smtp.smtp_data_code = 250
    fake_smtp.smtp_data_response = "OK"
    fake_smtp.sock = MagicMock(spec=ssl.SSLSocket)
    ssl_cls = MagicMock(return_value=fake_smtp)
    plain_cls = MagicMock()
    monkeypatch.setattr("app.smtp_service._LoggingSMTPSSL", ssl_cls)
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", plain_cls)

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    send_email(_params(port=465), message)

    ssl_cls.assert_called_once()
    plain_cls.assert_not_called()
    fake_smtp.starttls.assert_not_called()


def test_send_email_skips_login_when_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.send_message.return_value = {}
    fake_smtp.smtp_data_code = 250
    fake_smtp.smtp_data_response = "OK"
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", MagicMock(return_value=fake_smtp))

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    send_email(_params(port=25, username="", password=""), message)

    fake_smtp.login.assert_not_called()


def test_send_email_raises_on_refused_recipients(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    fake_smtp.send_message.return_value = {"ops@example.com": (550, b"no such user")}
    fake_smtp.sock = MagicMock(spec=ssl.SSLSocket)
    monkeypatch.setattr("app.smtp_service._LoggingSMTP", MagicMock(return_value=fake_smtp))

    message = build_message(from_address="alerts@example.com", subject="s", body="b", to_address="ops@example.com")
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        send_email(_params(port=25), message)


def test_smtp_friendly_error_dns_failure() -> None:
    err = socket.gaierror("Name or service not known")
    assert "Could not resolve hostname 'smtp.example.com'" in smtp_friendly_error(err, host="smtp.example.com")


def test_smtp_friendly_error_connection_refused() -> None:
    err = ConnectionRefusedError("refused")
    assert "was refused" in smtp_friendly_error(err, host="smtp.example.com")


def test_smtp_friendly_error_timeout() -> None:
    err = TimeoutError("timed out")
    assert "timed out" in smtp_friendly_error(err, host="smtp.example.com")


def test_smtp_friendly_error_auth_failure() -> None:
    err = smtplib.SMTPAuthenticationError(535, b"bad credentials")
    assert "Authentication failed" in smtp_friendly_error(err)


def test_smtp_friendly_error_auth_not_supported_suggests_blank_credentials() -> None:
    err = smtplib.SMTPNotSupportedError("AUTH extension not supported")
    assert "leave Username and Password blank" in smtp_friendly_error(err)


def test_smtp_friendly_error_recipients_refused() -> None:
    err = smtplib.SMTPRecipientsRefused({"ops@example.com": (550, b"no such user")})
    assert "refused 1 recipient" in smtp_friendly_error(err)


def test_smtp_friendly_error_generic_smtp_exception() -> None:
    err = smtplib.SMTPException("boom")
    assert smtp_friendly_error(err) == "SMTP error: boom"


def test_smtp_friendly_error_unrecognized_exception_falls_back_to_str() -> None:
    err = ValueError("something else")
    assert smtp_friendly_error(err) == "something else"


def test_smtp_friendly_error_not_encrypted() -> None:
    err = SmtpNotEncryptedError("Refusing to send SMTP credentials to smtp.example.com:25 over plaintext")
    assert "Refusing to send SMTP credentials" in smtp_friendly_error(err)
