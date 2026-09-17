"""SMTP delivery for home-warden's operator-configured relay (#57).

Ported from the-hcma/domesti-bot's app/smtp_service.py -- same connection/
delivery/error-translation shape, trimmed of what home-warden doesn't need
(rule-notification instance-URL templating). A single bounded-timeout
attempt per send, no retry loop: unlike a polled health check, a send is a
one-shot operator action (a test-send click, or a future heal-alert), and a
failure is either surfaced immediately to the operator or logged for the
next scheduled heal pass -- not something to spin on in place.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

_SMTP_TIMEOUT_SECONDS = 10.0


class SmtpNotEncryptedError(smtplib.SMTPException):
    """Raised when credentials would otherwise be sent over a plaintext
    connection -- see _maybe_login."""


@dataclass(frozen=True)
class SmtpConnectionParams:
    from_address: str
    host: str
    mail_domain: str
    password: str
    port: int
    username: str


@dataclass(frozen=True)
class SmtpDeliveryResult:
    host: str
    port: int
    recipients: tuple[str, ...]
    smtp_code: int
    smtp_response: str

    def format_for_log(self) -> str:
        parts = [
            f"smtp={self.smtp_code}",
            f"host={self.host}:{self.port}",
            f"recipient_count={len(self.recipients)}",
        ]
        response = self.smtp_response.strip()
        if response:
            parts.append(f"response={response!r}")
        return " ".join(parts)


class _LoggingSmtpMixin:
    smtp_data_code: int
    smtp_data_response: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.smtp_data_code = 0
        self.smtp_data_response = ""

    def data(self, msg: bytes | str) -> tuple[int, bytes]:
        code, resp = super().data(msg)  # type: ignore[misc]
        self.smtp_data_code = code
        self.smtp_data_response = resp.decode("utf-8", errors="replace") if isinstance(resp, bytes) else resp
        return code, resp


class _LoggingSMTP(_LoggingSmtpMixin, smtplib.SMTP):
    pass


class _LoggingSMTPSSL(_LoggingSmtpMixin, smtplib.SMTP_SSL):
    pass


def build_message(
    *,
    from_address: str,
    subject: str,
    body: str,
    to_address: str,
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)
    return message


def send_email(params: SmtpConnectionParams, message: EmailMessage) -> SmtpDeliveryResult:
    """Hand `message` to the configured relay. Raises the underlying
    socket/smtplib exception on failure -- callers translate it via
    smtp_friendly_error for anything operator-facing.
    """
    recipients = _message_recipients(message)
    use_ssl = params.port == 465
    smtp_cls = _LoggingSMTPSSL if use_ssl else _LoggingSMTP
    with smtp_cls(params.host, params.port, timeout=_SMTP_TIMEOUT_SECONDS) as smtp:
        smtp.ehlo_or_helo_if_needed()
        # Upgrade whenever the server offers it, not just on the
        # conventional submission ports -- credentials must never go out
        # on a connection that could have been encrypted but wasn't
        # because the port didn't match a hardcoded list.
        if not use_ssl and smtp.has_extn("starttls"):
            smtp.starttls()
            smtp.ehlo()
        _maybe_login(smtp, params)
        refused = smtp.send_message(message)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
        smtp_code = smtp.smtp_data_code
        smtp_response = smtp.smtp_data_response
    return SmtpDeliveryResult(
        host=params.host,
        port=params.port,
        recipients=recipients,
        smtp_code=smtp_code,
        smtp_response=smtp_response,
    )


def smtp_friendly_error(exc: Exception, *, host: str = "") -> str:
    """Translate a low-level socket/SMTP exception into an operator-readable message."""
    message = str(exc)
    host_label = f" '{host}'" if host else ""
    if isinstance(exc, socket.gaierror):
        return f"Could not resolve hostname{host_label} -- check that the SMTP host is correct."
    if isinstance(exc, ConnectionRefusedError):
        return (
            f"Connection to{host_label} was refused -- verify the host and port are correct "
            "and that no firewall is blocking the connection."
        )
    if isinstance(exc, TimeoutError):
        return (
            f"Connection to{host_label} timed out -- verify the host and port are correct "
            "and that no firewall is blocking the connection."
        )
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return f"Authentication failed -- check the username and password. ({message})"
    if isinstance(exc, smtplib.SMTPNotSupportedError) and "AUTH" in message:
        return (
            "The server does not support SMTP authentication. If this is an unauthenticated "
            "relay (e.g. a local or internal mail server), leave Username and Password blank."
        )
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return f"The server does not support a required feature -- check your TLS/SSL settings. ({message})"
    if isinstance(exc, smtplib.SMTPConnectError):
        return (
            f"Could not connect to the server{host_label} -- verify the host and port are "
            f"correct and the server is reachable. ({message})"
        )
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return f"SMTP relay refused {len(exc.recipients)} recipient(s) -- verify notification addresses are valid."
    if isinstance(exc, SmtpNotEncryptedError):
        return message
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP error: {message}"
    return message


def _maybe_login(smtp: smtplib.SMTP, params: SmtpConnectionParams) -> None:
    if params.username == "" and params.password == "":
        return
    if not isinstance(smtp.sock, ssl.SSLSocket):
        raise SmtpNotEncryptedError(
            f"Refusing to send SMTP credentials to {params.host}:{params.port} over an "
            "unencrypted connection -- the server did not offer STARTTLS and this isn't an "
            "implicit-TLS (port 465) connection. Use a relay/port that supports TLS, or leave "
            "Username and Password blank for an unauthenticated relay."
        )
    smtp.login(params.username, params.password)


def _message_recipients(message: EmailMessage) -> tuple[str, ...]:
    to_header = message.get("To", "")
    return tuple(part.strip() for part in to_header.split(",") if part.strip())
