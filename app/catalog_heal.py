"""Detect and heal drift across a catalog's cert/DNS/upstream health (#57):
reuses app.catalog_checks.run_all's existing four dimensions as the
trigger, then repairs what home-warden can actually fix on its own --

  cert -- ensure_cert (shared with #110's app.catalog_register: add
          server_name to conf/certbot-domains, then invoke
          scripts/cert-renewer unchanged).
  dns  -- sync_dns_record (#109's Cloudflare write path, reused as-is).

local_dns and upstream are alert-only, not healed here: #108 never grew a
live "add a record to zones.yml" primitive (only converter + verify +
reload-on-edit), and upstream health is a sibling service's own lifecycle
home-warden doesn't own (see AGENTS.md's Service Registration
Orchestration section and #57's own non-goals) -- surfacing loudly is the
honest "fix" for both.

Confirm-first like catalog_register: `apply=False` (the default) previews
every dimension without changing anything or sending any alert -- a dry
run is a manual look, not a scheduled pass, so it neither mutates
flap-protection state nor counts against the alert-resend window. Only a
real `--apply` run (the systemd timer's own invocation) touches
`heal_state_path()` or sends mail.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from app.catalog_checks import CheckResult, run_all, sync_dns_record
from app.catalog_register import ensure_cert
from app.smtp_config import SmtpConfig, smtp_send_ready
from app.smtp_service import SmtpConnectionParams, build_message, send_email, smtp_friendly_error

# CheckResult.dimension values app.catalog_heal can actually repair --
# "local_dns" and "upstream" are deliberately excluded, see module docstring.
_ACTIONABLE_DIMENSIONS = frozenset({"cert", "dns"})

# HealStepResult.action values that mean "this needs a human's attention" --
# drives both alert-worthiness and the "did this fail" exit-code check.
_ALERT_WORTHY_ACTIONS = frozenset({"alert-only", "failed", "cooldown"})


@dataclass
class HealStepResult:
    service: str
    dimension: str  # "cert" | "dns" | "local_dns" | "upstream"
    # "ok" | "skip" | "would-heal" | "healed" | "alert-only" | "cooldown" | "failed"
    action: str
    detail: str


def heal_catalog(
    catalog: dict,
    *,
    certs_live_dir: Path,
    alert_days: int,
    cf_headers: dict[str, str] | None,
    dns_target: str | None,
    local_dns_port: int,
    timeout: float,
    max_retries: int,
    apply: bool,
    proxied: bool = False,
    cloudflare_credentials: Path,
    certbot_domains_file: Path,
    cert_renewer: Path,
    cert_timeout: float = 600.0,
    state_path: Path,
    cooldown_seconds: float,
    max_attempts_per_window: int,
    attempt_window_seconds: float,
    resend_seconds: float,
    smtp_config: SmtpConfig | None,
    alert_to: str | None,
) -> list[HealStepResult]:
    checks = run_all(
        catalog,
        certs_live_dir=certs_live_dir,
        alert_days=alert_days,
        cf_headers=cf_headers,
        local_dns_port=local_dns_port,
        timeout=timeout,
        max_retries=max_retries,
    )

    services_by_name = {s.get("name", "<unnamed>"): s for s in catalog.get("services") or []}
    state = _load_state(state_path) if apply else {}
    now = time.time()

    results = [
        _heal_one(
            check,
            services_by_name.get(check.service) or {},
            state=state,
            now=now,
            dns_target=dns_target,
            cf_headers=cf_headers,
            timeout=timeout,
            max_retries=max_retries,
            apply=apply,
            proxied=proxied,
            cloudflare_credentials=cloudflare_credentials,
            certbot_domains_file=certbot_domains_file,
            cert_renewer=cert_renewer,
            cert_timeout=cert_timeout,
            cooldown_seconds=cooldown_seconds,
            max_attempts_per_window=max_attempts_per_window,
            attempt_window_seconds=attempt_window_seconds,
        )
        for check in checks
    ]

    if apply:
        for result in results:
            _maybe_alert(
                result, state, now=now, resend_seconds=resend_seconds, smtp_config=smtp_config, alert_to=alert_to
            )
        _save_state(state_path, state)

    return results


def _heal_one(
    check: CheckResult,
    service: dict,
    *,
    state: dict,
    now: float,
    dns_target: str | None,
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
    apply: bool,
    proxied: bool,
    cloudflare_credentials: Path,
    certbot_domains_file: Path,
    cert_renewer: Path,
    cert_timeout: float,
    cooldown_seconds: float,
    max_attempts_per_window: int,
    attempt_window_seconds: float,
) -> HealStepResult:
    if check.status in ("ok", "skip"):
        return HealStepResult(check.service, check.dimension, check.status, check.detail)

    # check.status == "fail" from here.
    if check.dimension not in _ACTIONABLE_DIMENSIONS:
        return HealStepResult(check.service, check.dimension, "alert-only", check.detail)

    if not apply:
        return HealStepResult(check.service, check.dimension, "would-heal", check.detail)

    key = f"{check.service}:{check.dimension}"
    entry = state.setdefault(key, {})
    window_start = entry.get("window_start_epoch", 0.0)
    attempts = entry.get("attempts", 0)
    last_attempt = entry.get("last_attempt_epoch", 0.0)

    if now - window_start > attempt_window_seconds:
        window_start, attempts = now, 0

    if last_attempt and now - last_attempt < cooldown_seconds:
        remaining = int(cooldown_seconds - (now - last_attempt))
        return HealStepResult(
            check.service, check.dimension, "cooldown", f"heal cooldown active, retry in {remaining}s"
        )
    if attempts >= max_attempts_per_window:
        return HealStepResult(
            check.service,
            check.dimension,
            "cooldown",
            f"heal attempt cap reached ({attempts}/{max_attempts_per_window} in this window)",
        )

    entry["window_start_epoch"] = window_start
    entry["attempts"] = attempts + 1
    entry["last_attempt_epoch"] = now

    if check.dimension == "cert":
        return _heal_cert(check, service, cloudflare_credentials, certbot_domains_file, cert_renewer, cert_timeout)
    return _heal_dns(check, service, dns_target, cf_headers, timeout, max_retries, proxied)


def _heal_cert(
    check: CheckResult,
    service: dict,
    cloudflare_credentials: Path,
    certbot_domains_file: Path,
    cert_renewer: Path,
    cert_timeout: float,
) -> HealStepResult:
    step = ensure_cert(
        service,
        certbot_domains_file,
        cert_renewer,
        cloudflare_credentials=cloudflare_credentials,
        apply=True,
        cert_timeout=cert_timeout,
    )
    action = {"applied": "healed", "skip": "skip"}.get(step.status, "failed")
    return HealStepResult(check.service, "cert", action, step.detail)


def _heal_dns(
    check: CheckResult,
    service: dict,
    dns_target: str | None,
    cf_headers: dict[str, str] | None,
    timeout: float,
    max_retries: int,
    proxied: bool,
) -> HealStepResult:
    if not dns_target:
        return HealStepResult(check.service, "dns", "failed", "no dns_target configured -- cannot heal external DNS")
    sync = sync_dns_record(
        check.service, service, dns_target, cf_headers, timeout, max_retries, proxied=proxied, dry_run=False
    )
    action = {"created": "healed", "updated": "healed", "noop": "healed", "skip": "skip"}.get(sync.status, "failed")
    return HealStepResult(check.service, "dns", action, sync.detail)


def _maybe_alert(
    result: HealStepResult,
    state: dict,
    *,
    now: float,
    resend_seconds: float,
    smtp_config: SmtpConfig | None,
    alert_to: str | None,
) -> None:
    key = f"{result.service}:{result.dimension}:alert"
    entry = state.setdefault(key, {})
    was_bad = entry.get("last_status") == "bad"
    is_bad = result.action in _ALERT_WORTHY_ACTIONS
    entry["last_status"] = "bad" if is_bad else "good"

    if is_bad:
        due_for_resend = now - entry.get("last_alert_epoch", 0.0) >= resend_seconds
        if was_bad and not due_for_resend:
            return
        _send_alert(
            subject=f"home-warden catalog-heal: {result.service}/{result.dimension} needs attention",
            body=f"action={result.action}\n{result.detail}",
            smtp_config=smtp_config,
            alert_to=alert_to,
        )
        entry["last_alert_epoch"] = now
    elif was_bad:
        _send_alert(
            subject=f"home-warden catalog-heal: {result.service}/{result.dimension} recovered",
            body=result.detail,
            smtp_config=smtp_config,
            alert_to=alert_to,
        )


def _send_alert(*, subject: str, body: str, smtp_config: SmtpConfig | None, alert_to: str | None) -> None:
    # Never raise out of alerting -- a broken relay must not turn a
    # detected/healed drift into an unhandled traceback that skips the
    # rest of this run's reporting.
    if not alert_to:
        print(f"catalog-heal: ALERT (no CATALOG_HEAL_ALERT_TO configured): {subject}\n{body}", file=sys.stderr)
        return
    if not smtp_send_ready(smtp_config):
        print(f"catalog-heal: ALERT (SMTP not configured): {subject}\n{body}", file=sys.stderr)
        return
    assert smtp_config is not None  # smtp_send_ready(None) is False
    params = SmtpConnectionParams(
        from_address=smtp_config.from_address,
        host=smtp_config.host,
        mail_domain=smtp_config.mail_domain,
        password=smtp_config.password,
        port=smtp_config.port,
        username=smtp_config.username,
    )
    message = build_message(from_address=params.from_address, subject=subject, body=body, to_address=alert_to)
    try:
        send_email(params, message)
    except Exception as e:
        friendly = smtp_friendly_error(e, host=params.host)
        print(f"catalog-heal: ALERT SEND FAILED ({friendly}): {subject}\n{body}", file=sys.stderr)


def _load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(state, indent=2).encode("utf-8"))
    finally:
        os.close(fd)
    tmp.replace(path)
