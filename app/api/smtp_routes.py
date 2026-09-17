"""Authenticated SMTP settings routes for the web UI (#57)."""

from __future__ import annotations

from http import HTTPStatus

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.catalog_health_settings import enforce_host_guard
from app.smtp_config import (
    SmtpConfig,
    SmtpConfigUpdate,
    delete_smtp_config,
    load_smtp_config,
    save_smtp_config,
)
from app.smtp_service import SmtpConnectionParams, build_message, send_email, smtp_friendly_error

router = APIRouter(prefix="/settings", tags=["settings"])


class SmtpConfigIn(BaseModel):
    from_address: str
    host: str
    mail_domain: str
    password: str | None = None
    port: int
    username: str


class SmtpConfigOut(BaseModel):
    from_address: str
    host: str
    mail_domain: str
    password_configured: bool
    port: int
    username: str


class SmtpTestEmailIn(SmtpConfigIn):
    to_address: str


class SmtpTestEmailOut(BaseModel):
    message: str
    ok: bool


@router.delete("/smtp", status_code=HTTPStatus.NO_CONTENT)
def delete_smtp_settings_route() -> None:
    _require_host_guard("smtp-settings-delete-api")
    delete_smtp_config()


@router.get("/smtp", response_model=SmtpConfigOut | None)
def get_smtp_settings() -> SmtpConfigOut | None:
    _require_host_guard("smtp-settings-get-api")
    config = load_smtp_config()
    if config is None:
        return None
    return _to_schema(config)


@router.put("/smtp", response_model=SmtpConfigOut)
def put_smtp_settings(body: SmtpConfigIn) -> SmtpConfigOut:
    _require_host_guard("smtp-settings-put-api")
    _validate_smtp_body(body)
    saved = save_smtp_config(
        SmtpConfigUpdate(
            from_address=body.from_address,
            host=body.host,
            mail_domain=body.mail_domain,
            password=body.password,
            port=body.port,
            username=body.username,
        )
    )
    return _to_schema(saved)


@router.post("/smtp/test", response_model=SmtpTestEmailOut)
def post_smtp_test_email(body: SmtpTestEmailIn) -> SmtpTestEmailOut:
    _require_host_guard("smtp-settings-test-api")
    _validate_smtp_body(body)
    if body.to_address.strip() == "":
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="Expected recipient email, got empty value"
        )

    password = _resolve_test_password(body)
    params = SmtpConnectionParams(
        from_address=body.from_address.strip(),
        host=body.host.strip(),
        mail_domain=body.mail_domain.strip(),
        password=password,
        port=body.port,
        username=body.username.strip(),
    )
    message = build_message(
        from_address=params.from_address,
        subject="home-warden SMTP test",
        body=f"This is a test email from home-warden ({params.mail_domain}). SMTP settings are working.",
        to_address=body.to_address.strip(),
    )
    try:
        send_email(params, message)
    except Exception as exc:
        return SmtpTestEmailOut(ok=False, message=smtp_friendly_error(exc, host=params.host))
    return SmtpTestEmailOut(ok=True, message=f"Test email sent to {body.to_address.strip()}")


def _require_host_guard(caller: str) -> None:
    if not enforce_host_guard(caller):
        raise HTTPException(
            status_code=503,
            detail="this host is not the designated home-warden host (see scripts/lib/host-guard)",
        )


def _resolve_test_password(body: SmtpTestEmailIn) -> str:
    """Reuse the stored password only when the draft is blank AND still
    points at the same host the stored password belongs to -- otherwise an
    operator testing a *different* relay would silently authenticate
    against it with credentials for the old one.
    """
    if body.password is not None and body.password != "":
        return body.password
    existing = load_smtp_config()
    if existing is None or existing.host.strip() != body.host.strip():
        return ""
    return existing.password


def _to_schema(config: SmtpConfig) -> SmtpConfigOut:
    return SmtpConfigOut(
        from_address=config.from_address,
        host=config.host,
        mail_domain=config.mail_domain,
        password_configured=bool(config.password.strip()),
        port=config.port,
        username=config.username,
    )


def _validate_smtp_body(body: SmtpConfigIn) -> None:
    if body.host.strip() == "":
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="Expected SMTP host, got empty value")
    if body.mail_domain.strip() == "":
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="Expected mail domain, got empty value")
    if body.from_address.strip() == "":
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail="Expected from address, got empty value"
        )
