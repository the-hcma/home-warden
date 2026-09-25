"""Tests for app.catalog_heal. Every dependency (catalog_checks' run_all/
sync_dns_record, catalog_register's ensure_cert, smtp_service's send_email)
is mocked -- see AGENTS.md's Python Conventions ("tests must not depend on
live infrastructure or credentials").
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from app.catalog_checks import CheckResult, SyncResult
from app.catalog_heal import HealStepResult, _load_state, _save_state, heal_catalog
from app.catalog_register import RegisterStepResult
from app.smtp_config import SmtpConfig

CATALOG = {"services": [{"name": "svc", "kind": "proxy", "server_name": "app.example.com"}]}

CERT_OK = CheckResult("svc", "cert", "ok", "valid")
CERT_FAIL = CheckResult("svc", "cert", "fail", "expires soon")
DNS_OK = CheckResult("svc", "dns", "ok", "resolves")
DNS_FAIL = CheckResult("svc", "dns", "fail", "missing record")
LOCAL_DNS_FAIL = CheckResult("svc", "local_dns", "fail", "no local record")
LOCAL_DNS_SKIP = CheckResult("svc", "local_dns", "skip", "not our zone")
UPSTREAM_FAIL = CheckResult("svc", "upstream", "fail", "unreachable")

SMTP_READY = SmtpConfig(from_address="warden@example.com", host="smtp.example.com", mail_domain="example.com", port=587)


def _heal(
    checks: list[CheckResult],
    *,
    apply_cert: bool,
    apply_dns: bool,
    state_path: Path,
    dns_target: str | None = "203.0.113.10",
    cooldown_seconds: float = 3600,
    max_attempts_per_window: int = 3,
    attempt_window_seconds: float = 86400,
    resend_seconds: float = 21600,
    smtp_config: SmtpConfig | None = None,
    alert_to: str | None = "ops@example.com",
) -> list[HealStepResult]:
    with patch("app.catalog_heal.run_all", return_value=checks):
        return heal_catalog(
            CATALOG,
            certs_live_dir=Path("/tmp/certs"),
            alert_days=10,
            cf_headers={"X-Auth-Email": "x"},
            dns_target=dns_target,
            local_dns_port=853,
            timeout=5,
            max_retries=3,
            apply_cert=apply_cert,
            apply_dns=apply_dns,
            cloudflare_credentials=Path("/tmp/cloudflare.ini"),
            certbot_domains_file=Path("/tmp/certbot-domains"),
            cert_renewer=Path("/tmp/cert-renewer"),
            state_path=state_path,
            cooldown_seconds=cooldown_seconds,
            max_attempts_per_window=max_attempts_per_window,
            attempt_window_seconds=attempt_window_seconds,
            resend_seconds=resend_seconds,
            smtp_config=smtp_config,
            alert_to=alert_to,
        )


# --- pass-through / alert-only dimensions ------------------------------------


def test_ok_and_skip_checks_pass_through_unchanged(tmp_path: Path) -> None:
    results = _heal([CERT_OK, LOCAL_DNS_SKIP], apply_cert=False, apply_dns=False, state_path=tmp_path / "state.json")
    assert results == [
        HealStepResult("svc", "cert", "ok", "valid"),
        HealStepResult("svc", "local_dns", "skip", "not our zone"),
    ]


def test_local_dns_failure_is_alert_only_never_heals(tmp_path: Path) -> None:
    results = _heal([LOCAL_DNS_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "local_dns", "alert-only", "no local record")]


def test_upstream_failure_is_alert_only_never_heals(tmp_path: Path) -> None:
    results = _heal([UPSTREAM_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "upstream", "alert-only", "unreachable")]


# --- dry run -------------------------------------------------------------


def test_dry_run_reports_would_heal_without_acting(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.ensure_cert") as mock_cert, patch("app.catalog_heal.sync_dns_record") as mock_dns:
        results = _heal([CERT_FAIL, DNS_FAIL], apply_cert=False, apply_dns=False, state_path=state_path)
    mock_cert.assert_not_called()
    mock_dns.assert_not_called()
    assert [r.action for r in results] == ["would-heal", "would-heal"]
    assert not state_path.exists()


def test_dry_run_never_sends_alerts(tmp_path: Path) -> None:
    with patch("app.catalog_heal._send_alert") as mock_alert:
        _heal([LOCAL_DNS_FAIL], apply_cert=False, apply_dns=False, state_path=tmp_path / "state.json")
    mock_alert.assert_not_called()


# --- cert heal -------------------------------------------------------------


def test_cert_heal_applied_reports_healed(tmp_path: Path) -> None:
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")):
        results = _heal([CERT_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "cert", "healed", "renewed")]


def test_cert_heal_failure_reported(tmp_path: Path) -> None:
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "failed", "certbot error")):
        results = _heal([CERT_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "cert", "failed", "certbot error")]


def test_cert_heal_skip_reported(tmp_path: Path) -> None:
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "skip", "no server_name")):
        results = _heal([CERT_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "cert", "skip", "no server_name")]


# --- external DNS heal -------------------------------------------------------


def test_dns_heal_created_reports_healed(tmp_path: Path) -> None:
    with patch("app.catalog_heal.sync_dns_record", return_value=SyncResult("svc", "created", "A record created")):
        results = _heal([DNS_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "dns", "healed", "A record created")]


def test_dns_heal_failed_reported(tmp_path: Path) -> None:
    with patch("app.catalog_heal.sync_dns_record", return_value=SyncResult("svc", "failed", "zone not found")):
        results = _heal([DNS_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json")
    assert results == [HealStepResult("svc", "dns", "failed", "zone not found")]


def test_dns_heal_without_target_fails_without_calling_sync(tmp_path: Path) -> None:
    with patch("app.catalog_heal.sync_dns_record") as mock_dns:
        results = _heal(
            [DNS_FAIL], apply_cert=True, apply_dns=True, dns_target=None, state_path=tmp_path / "state.json"
        )
    mock_dns.assert_not_called()
    assert results[0].action == "failed"
    assert "dns_target" in results[0].detail


# --- per-dimension apply split (the timer passes apply_cert alone) ----------


def test_apply_cert_without_apply_dns_heals_cert_but_alerts_dns(tmp_path: Path) -> None:
    # This is the systemd timer's exact invocation shape: cert renewal
    # is safe to run unattended, external-DNS repair is not, so the timer
    # never sets apply_dns. A real DNS write here would be the bug this
    # test exists to catch.
    with (
        patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")),
        patch("app.catalog_heal.sync_dns_record") as mock_dns,
    ):
        results = _heal([CERT_FAIL, DNS_FAIL], apply_cert=True, apply_dns=False, state_path=tmp_path / "state.json")
    mock_dns.assert_not_called()
    assert results == [
        HealStepResult("svc", "cert", "healed", "renewed"),
        HealStepResult("svc", "dns", "alert-only", "missing record"),
    ]


def test_apply_dns_without_apply_cert_heals_dns_but_alerts_cert(tmp_path: Path) -> None:
    with (
        patch("app.catalog_heal.ensure_cert") as mock_cert,
        patch("app.catalog_heal.sync_dns_record", return_value=SyncResult("svc", "created", "A record created")),
    ):
        results = _heal([CERT_FAIL, DNS_FAIL], apply_cert=False, apply_dns=True, state_path=tmp_path / "state.json")
    mock_cert.assert_not_called()
    assert results == [
        HealStepResult("svc", "cert", "alert-only", "expires soon"),
        HealStepResult("svc", "dns", "healed", "A record created"),
    ]


def test_apply_cert_alone_is_a_real_run_and_sends_alerts(tmp_path: Path) -> None:
    # apply_cert alone still counts as a real run (not a dry preview): the
    # DNS alert-only result above must actually reach the operator, not
    # silently no-op the way a dry run would.
    with patch("app.catalog_heal.send_email") as mock_send:
        with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")):
            _heal(
                [CERT_FAIL, DNS_FAIL],
                apply_cert=True,
                apply_dns=False,
                state_path=tmp_path / "state.json",
                smtp_config=SMTP_READY,
            )
    mock_send.assert_called_once()


# --- flap protection ---------------------------------------------------------


def test_cooldown_blocks_repeat_heal_within_window(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")) as mc:
        first = _heal([CERT_FAIL], apply_cert=True, apply_dns=True, state_path=state_path, cooldown_seconds=3600)
        second = _heal([CERT_FAIL], apply_cert=True, apply_dns=True, state_path=state_path, cooldown_seconds=3600)
    assert first[0].action == "healed"
    assert second[0].action == "cooldown"
    assert mc.call_count == 1


def test_attempt_cap_blocks_further_heals_in_window(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")) as mc:
        first = _heal(
            [CERT_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            cooldown_seconds=0,
            max_attempts_per_window=1,
        )
        second = _heal(
            [CERT_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            cooldown_seconds=0,
            max_attempts_per_window=1,
        )
    assert first[0].action == "healed"
    assert second[0].action == "cooldown"
    assert "attempt cap" in second[0].detail
    assert mc.call_count == 1


def test_attempt_window_reset_allows_heal_again(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps({"svc:cert": {"window_start_epoch": 0.0, "attempts": 5, "last_attempt_epoch": 0.0}})
    )
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")) as mc:
        results = _heal(
            [CERT_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            cooldown_seconds=10,
            max_attempts_per_window=1,
            attempt_window_seconds=1,
        )
    assert results[0].action == "healed"
    mc.assert_called_once()


# --- alerting -----------------------------------------------------------


def test_alert_sent_on_new_failure(tmp_path: Path) -> None:
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=tmp_path / "state.json",
            smtp_config=SMTP_READY,
        )
    mock_send.assert_called_once()


def test_alert_sent_on_cooldown_block(tmp_path: Path) -> None:
    # _ALERT_WORTHY_ACTIONS includes "cooldown" alongside "alert-only" and
    # "failed" -- exercise it explicitly (both prior heal-flow tests run
    # with smtp_config=None) so dropping "cooldown" from that set can't
    # keep the whole suite green while silencing a real flap alert.
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.ensure_cert", return_value=RegisterStepResult("cert", "applied", "renewed")):
        with patch("app.catalog_heal.send_email") as mock_send:
            _heal(
                [CERT_FAIL],
                apply_cert=True,
                apply_dns=True,
                state_path=state_path,
                smtp_config=SMTP_READY,
                cooldown_seconds=3600,
            )
        mock_send.assert_not_called()  # first attempt heals cleanly, nothing to alert on yet
        with patch("app.catalog_heal.send_email") as mock_send:
            _heal(
                [CERT_FAIL],
                apply_cert=True,
                apply_dns=True,
                state_path=state_path,
                smtp_config=SMTP_READY,
                cooldown_seconds=3600,
            )
    mock_send.assert_called_once()
    state = _load_state(state_path)
    assert state["svc:cert:alert"]["last_status"] == "bad"


def test_alert_not_resent_before_resend_window(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
            resend_seconds=3600,
        )
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
            resend_seconds=3600,
        )
    assert mock_send.call_count == 1


def test_alert_resent_after_resend_window_elapses(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
            resend_seconds=3600,
        )
    state = _load_state(state_path)
    state["svc:local_dns:alert"]["last_alert_epoch"] = 0.0  # pretend the last alert was long ago
    _save_state(state_path, state)
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
            resend_seconds=3600,
        )
    assert mock_send.call_count == 1


def test_recovery_alert_sent_once_when_fixed(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal([LOCAL_DNS_FAIL], apply_cert=True, apply_dns=True, state_path=state_path, smtp_config=SMTP_READY)
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [CheckResult("svc", "local_dns", "ok", "fixed")],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
        )
        mock_send.assert_called_once()
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [CheckResult("svc", "local_dns", "ok", "fixed")],
            apply_cert=True,
            apply_dns=True,
            state_path=state_path,
            smtp_config=SMTP_READY,
        )
    mock_send.assert_not_called()


def test_no_alert_when_always_healthy(tmp_path: Path) -> None:
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [CERT_OK, DNS_OK],
            apply_cert=True,
            apply_dns=True,
            state_path=tmp_path / "state.json",
            smtp_config=SMTP_READY,
        )
    mock_send.assert_not_called()


def test_alert_without_recipient_logs_to_stderr_not_email(tmp_path: Path, capsys) -> None:
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=tmp_path / "state.json",
            smtp_config=SMTP_READY,
            alert_to=None,
        )
    mock_send.assert_not_called()
    assert "no CATALOG_HEAL_ALERT_TO" in capsys.readouterr().err


def test_alert_without_smtp_configured_logs_to_stderr(tmp_path: Path, capsys) -> None:
    with patch("app.catalog_heal.send_email") as mock_send:
        _heal([LOCAL_DNS_FAIL], apply_cert=True, apply_dns=True, state_path=tmp_path / "state.json", smtp_config=None)
    mock_send.assert_not_called()
    assert "SMTP not configured" in capsys.readouterr().err


def test_alert_send_exception_does_not_propagate(tmp_path: Path, capsys) -> None:
    with patch("app.catalog_heal.send_email", side_effect=OSError("connection refused")):
        results = _heal(
            [LOCAL_DNS_FAIL],
            apply_cert=True,
            apply_dns=True,
            state_path=tmp_path / "state.json",
            smtp_config=SMTP_READY,
        )
    assert results == [HealStepResult("svc", "local_dns", "alert-only", "no local record")]
    assert "ALERT SEND FAILED" in capsys.readouterr().err


# --- state file I/O -----------------------------------------------------


def test_load_state_missing_file_is_empty(tmp_path: Path) -> None:
    assert _load_state(tmp_path / "missing.json") == {}


def test_load_state_corrupt_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{not json")
    assert _load_state(path) == {}


def test_save_and_load_state_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state.json"
    state = {"svc:cert": {"attempts": 1}}
    _save_state(path, state)
    assert _load_state(path) == state
    assert oct(path.stat().st_mode)[-3:] == "600"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
