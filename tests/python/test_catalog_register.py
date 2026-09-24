"""Tests for app.catalog_register. Every dependency (catalog_checks'
check_local_dns/check_upstream/sync_dns_record, catalog_crud's
get_service/render_preview, and the cert-renewer subprocess call) is
mocked -- see AGENTS.md's Python Conventions ("tests must not depend on
live infrastructure or credentials").
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from app.catalog_checks import CheckResult, SyncResult
from app.catalog_crud import CatalogNotFoundError, CatalogValidationError, GixyResult, NginxTestResult, PreviewResult
from app.catalog_register import RegisterStepResult, _append_domain, _read_domains, register_service

CATALOG = {"services": [{"name": "svc", "kind": "proxy", "server_name": "app.example.com"}]}
LOCAL_DNS_FAIL = CheckResult("svc", "local_dns", "fail", "no record")
LOCAL_DNS_OK = CheckResult("svc", "local_dns", "ok", "resolves")
UPSTREAM_FAIL = CheckResult("svc", "upstream", "fail", "unreachable")
UPSTREAM_OK = CheckResult("svc", "upstream", "ok", "up")
OK_PREVIEW = PreviewResult(
    can_apply=True,
    diff="",
    gixy=GixyResult(exit_code=0, output="", status="ok"),
    nginx_test=NginxTestResult(exit_code=0, ok=True, output="syntax ok", status="ok"),
    rendered="",
)
FAILED_PREVIEW = PreviewResult(
    can_apply=False,
    diff="",
    gixy=GixyResult(exit_code=0, output="", status="ok"),
    nginx_test=NginxTestResult(exit_code=1, ok=False, output="nginx: [emerg] bad directive", status="failed"),
    rendered="",
)
GIXY_FINDINGS_PREVIEW = PreviewResult(
    can_apply=True,
    diff="",
    gixy=GixyResult(exit_code=1, output="server_tokens: version disclosure", status="findings"),
    nginx_test=NginxTestResult(exit_code=0, ok=True, output="syntax ok", status="ok"),
    rendered="",
)


def _base_kwargs(**overrides) -> dict:
    kwargs = {
        "dns_target": "203.0.113.10",
        "cf_headers": {"Authorization": "Bearer x"},
        "cloudflare_credentials": Path("/nonexistent/cloudflare.ini"),
        "certbot_domains_file": Path("/nonexistent/certbot-domains"),
        "cert_renewer": Path("/nonexistent/cert-renewer"),
        "services_json_path": Path("/nonexistent/services.json"),
        "local_dns_port": 853,
        "timeout": 5,
        "max_retries": 1,
        "apply": False,
    }
    kwargs.update(overrides)
    return kwargs


def test_register_service_not_found_is_single_failed_catalog_step() -> None:
    with patch("app.catalog_register.get_service", side_effect=CatalogNotFoundError("service 'svc' not found")):
        results = register_service("svc", CATALOG, **_base_kwargs())
    assert len(results) == 1
    assert results[0].step == "catalog"
    assert results[0].status == "failed"


def test_register_service_stops_at_failed_local_dns() -> None:
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_FAIL),
        patch("app.catalog_register.check_upstream") as mock_upstream,
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    mock_upstream.assert_not_called()
    assert len(results) == 1
    assert results[0].step == "local_dns"
    assert results[0].status == "failed"


def test_register_service_local_dns_fail_status_normalized_to_failed() -> None:
    # CheckResult spells failure "fail"; RegisterStepResult must normalize
    # to "failed" so a uniform any(status == "failed") check works across
    # every step, including the ones backed by CheckResult vs SyncResult.
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_FAIL),
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    assert results[0].status == "failed"


def test_register_service_stops_at_failed_upstream() -> None:
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_FAIL),
        patch("app.catalog_register.sync_dns_record") as mock_sync,
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    mock_sync.assert_not_called()
    assert [r.step for r in results] == ["local_dns", "upstream"]
    assert results[-1].status == "failed"


def test_register_service_stops_at_failed_external_dns() -> None:
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "failed", "Cloudflare error")),
        patch("app.catalog_register._ensure_cert") as mock_cert,
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    mock_cert.assert_not_called()
    assert [r.step for r in results] == ["local_dns", "upstream", "external_dns"]
    assert results[-1].status == "failed"


def test_register_service_preview_mode_reaches_nginx_step() -> None:
    # apply=False (preview/confirm-first): external_dns reports
    # would-create (not "failed"), so the pipeline still proceeds through
    # cert and nginx to show the full plan.
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch(
            "app.catalog_register.sync_dns_record",
            return_value=SyncResult("svc", "would-create", "would create A app.example.com -> 203.0.113.10"),
        ) as mock_sync,
        patch("app.catalog_register.render_preview", return_value=OK_PREVIEW),
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    assert [r.step for r in results] == ["local_dns", "upstream", "external_dns", "cert", "nginx"]
    assert results[3].status == "would-apply"
    assert results[4].status == "ok"
    assert not any(r.status == "failed" for r in results)
    # This is the only thing that makes apply=False non-mutating -- pin
    # the polarity, not just the returned result, so a swapped
    # dry_run=apply would fail here instead of only in production.
    assert mock_sync.call_args.kwargs["dry_run"] is True
    assert mock_sync.call_args.kwargs["proxied"] is False


def test_register_service_cert_skip_when_no_server_name() -> None:
    service = {"name": "svc", "kind": "static"}
    with (
        patch("app.catalog_register.get_service", return_value=service),
        patch("app.catalog_register.check_local_dns", return_value=CheckResult("svc", "local_dns", "skip", "static")),
        patch("app.catalog_register.check_upstream", return_value=CheckResult("svc", "upstream", "skip", "static")),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "skip", "no server_name")),
        patch("app.catalog_register.render_preview", return_value=OK_PREVIEW),
    ):
        results = register_service("svc", CATALOG, **_base_kwargs())
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "skip"


def test_register_service_cert_renewer_failure_stops_before_nginx() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="certbot: DNS challenge failed")
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")),
        patch("app.catalog_register._read_domains", return_value=set()),
        patch("app.catalog_register._append_domain"),
        patch("subprocess.run", return_value=completed),
        patch("app.catalog_register.render_preview") as mock_render,
    ):
        results = register_service("svc", CATALOG, **_base_kwargs(apply=True))
    mock_render.assert_not_called()
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "failed"
    assert "DNS challenge failed" in cert_result.detail


def test_register_service_cert_renewer_timeout_is_failed() -> None:
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")),
        patch("app.catalog_register._read_domains", return_value=set()),
        patch("app.catalog_register._append_domain"),
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cert-renewer", timeout=600)),
    ):
        results = register_service("svc", CATALOG, **_base_kwargs(apply=True))
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "failed"


def test_register_service_cert_renewer_permission_error_is_failed_not_raised() -> None:
    # A non-executable cert_renewer (or any other subprocess-launch
    # OSError, e.g. EACCES) raises PermissionError, which is an OSError
    # but neither FileNotFoundError nor TimeoutExpired -- must not escape
    # as an unhandled traceback after external_dns/cert-domains-append
    # have already mutated state.
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")),
        patch("app.catalog_register._read_domains", return_value=set()),
        patch("app.catalog_register._append_domain"),
        patch("subprocess.run", side_effect=PermissionError("[Errno 13] Permission denied")),
    ):
        results = register_service("svc", CATALOG, **_base_kwargs(apply=True))
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "failed"


def test_register_service_apply_appends_domain_only_when_not_already_listed() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")),
        patch("app.catalog_register._read_domains", return_value={"app.example.com"}),
        patch("app.catalog_register._append_domain") as mock_append,
        patch("subprocess.run", return_value=completed),
        patch("app.catalog_register.render_preview", return_value=OK_PREVIEW),
    ):
        register_service("svc", CATALOG, **_base_kwargs(apply=True))
    mock_append.assert_not_called()


def test_register_service_apply_wires_dry_run_and_appends_missing_domain() -> None:
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    certbot_domains_file = Path("/nonexistent/certbot-domains")
    cloudflare_credentials = Path("/nonexistent/cloudflare.ini")
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch(
            "app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")
        ) as mock_sync,
        # First call (pre-append check) sees no domains; second (post-run
        # verification, after cert-renewer "ran") sees the appended one --
        # a fixed return_value would either always fail the post-check or
        # never exercise it.
        patch("app.catalog_register._read_domains", side_effect=[set(), {"app.example.com"}]),
        patch("app.catalog_register._append_domain") as mock_append,
        patch("subprocess.run", return_value=completed) as mock_run,
        patch("app.catalog_register.render_preview", return_value=OK_PREVIEW),
    ):
        results = register_service(
            "svc",
            CATALOG,
            **_base_kwargs(
                apply=True,
                proxied=True,
                certbot_domains_file=certbot_domains_file,
                cloudflare_credentials=cloudflare_credentials,
            ),
        )
    assert mock_sync.call_args.kwargs["dry_run"] is False
    assert mock_sync.call_args.kwargs["proxied"] is True
    mock_append.assert_called_once_with(certbot_domains_file, "app.example.com")
    assert mock_run.call_args.kwargs["env"]["CERTBOT_DOMAINS_FILE"] == str(certbot_domains_file)
    assert mock_run.call_args.kwargs["env"]["CLOUDFLARE_CREDENTIALS"] == str(cloudflare_credentials)
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "applied"


def test_register_service_cert_reports_failed_when_domain_lost_after_run() -> None:
    # scripts/link-runtime-conf (called internally by cert-renewer) can
    # replace certbot_domains_file with a symlink to a different file in
    # a linked worktree, discarding the append -- a 0 exit code alone
    # must not be trusted as proof the domain reached certbot.
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "created", "created")),
        patch("app.catalog_register._read_domains", side_effect=[set(), set()]),
        patch("app.catalog_register._append_domain"),
        patch("subprocess.run", return_value=completed),
        patch("app.catalog_register.render_preview") as mock_render,
    ):
        results = register_service("svc", CATALOG, **_base_kwargs(apply=True))
    mock_render.assert_not_called()
    cert_result = next(r for r in results if r.step == "cert")
    assert cert_result.status == "failed"
    assert "missing from" in cert_result.detail


def test_register_service_nginx_validation_failure_is_reported() -> None:
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "noop", "already correct")),
        patch("app.catalog_register._ensure_cert") as mock_cert,
        patch("app.catalog_register.render_preview", return_value=FAILED_PREVIEW),
    ):
        mock_cert.return_value = RegisterStepResult("cert", "applied", "cert ok")
        results = register_service("svc", CATALOG, **_base_kwargs())
    nginx_result = next(r for r in results if r.step == "nginx")
    assert nginx_result.status == "failed"
    assert "bad directive" in nginx_result.detail


def test_register_service_nginx_step_fails_on_gixy_findings_even_when_nginx_t_passes() -> None:
    # preview.can_apply reflects nginx -t alone (app.catalog_crud's own
    # gate) -- a Gixy finding must not be silently folded into an "ok"
    # "both pass" claim just because can_apply itself doesn't see it.
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "noop", "already correct")),
        patch("app.catalog_register._ensure_cert") as mock_cert,
        patch("app.catalog_register.render_preview", return_value=GIXY_FINDINGS_PREVIEW),
    ):
        mock_cert.return_value = RegisterStepResult("cert", "applied", "cert ok")
        results = register_service("svc", CATALOG, **_base_kwargs())
    nginx_result = next(r for r in results if r.step == "nginx")
    assert nginx_result.status == "failed"
    assert "version disclosure" in nginx_result.detail


def test_register_service_nginx_step_reports_invalid_catalog_instead_of_raising() -> None:
    # render_preview raises CatalogValidationError for a shape-valid-JSON
    # but renderer-invalid catalog (this entry or any sibling) -- sibling
    # consumers (render-catalog, the catalog CRUD routes) already map
    # this to a config error; this step must too, not let it escape and
    # lose the "which step failed" contract the CLI depends on.
    with (
        patch("app.catalog_register.get_service", return_value=CATALOG["services"][0]),
        patch("app.catalog_register.check_local_dns", return_value=LOCAL_DNS_OK),
        patch("app.catalog_register.check_upstream", return_value=UPSTREAM_OK),
        patch("app.catalog_register.sync_dns_record", return_value=SyncResult("svc", "noop", "already correct")),
        patch("app.catalog_register._ensure_cert") as mock_cert,
        patch("app.catalog_register.render_preview", side_effect=CatalogValidationError("service 'x' bad")),
    ):
        mock_cert.return_value = RegisterStepResult("cert", "applied", "cert ok")
        results = register_service("svc", CATALOG, **_base_kwargs())
    nginx_result = next(r for r in results if r.step == "nginx")
    assert nginx_result.status == "failed"
    assert "service 'x' bad" in nginx_result.detail


# --- _read_domains / _append_domain -----------------------------------------


def test_read_domains_missing_file_is_empty_set() -> None:
    assert _read_domains(Path("/nonexistent/certbot-domains")) == set()


def test_read_domains_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "certbot-domains"
    path.write_text("# comment\n\napp.example.com\n  other.example.com  \n")
    assert _read_domains(path) == {"app.example.com", "other.example.com"}


def test_append_domain_creates_parent_and_appends(tmp_path: Path) -> None:
    path = tmp_path / "conf" / "certbot-domains"
    _append_domain(path, "app.example.com")
    _append_domain(path, "other.example.com")
    assert path.read_text() == "app.example.com\nother.example.com\n"


def test_append_domain_inserts_missing_leading_newline(tmp_path: Path) -> None:
    # A file whose last line has no trailing newline (e.g. printf-written,
    # or an editor that strips the final newline) must not have its last
    # domain merged with the appended one into one bogus line.
    path = tmp_path / "certbot-domains"
    path.write_text("app.example.com")
    _append_domain(path, "other.example.com")
    assert path.read_text() == "app.example.com\nother.example.com\n"
