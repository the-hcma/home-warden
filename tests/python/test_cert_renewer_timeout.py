"""scripts/cert-renewer bounds every certbot run by CERTBOT_TIMEOUT_SEC.

Runs the real script against a stub certbot, in --dry-run so it never
touches cert permissions or reloads nginx.
"""

import os
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CERT_RENEWER = REPO / "scripts" / "cert-renewer"


def test_certbot_run_within_the_limit_succeeds(tmp_path: Path) -> None:
    result = _run(tmp_path, stub_body='echo "$@" >"$(dirname "$0")/args"', timeout_sec="5")
    assert result.returncode == 0, result.stderr
    args = (tmp_path / "args").read_text()
    assert args.startswith("certonly -d app.example.com ")
    assert "--dry-run" in args


def test_hung_certbot_is_killed_and_fails_the_renewer(tmp_path: Path) -> None:
    started = time.monotonic()
    result = _run(tmp_path, stub_body="exec sleep 60", timeout_sec="1")
    assert result.returncode == 124
    assert "certbot certonly timed out after 1s (CERTBOT_TIMEOUT_SEC)" in result.stderr
    assert time.monotonic() - started < 30


def test_invalid_timeout_is_a_usage_error(tmp_path: Path) -> None:
    result = _run(tmp_path, stub_body="exit 0", timeout_sec="0")
    assert result.returncode == 2
    assert "CERTBOT_TIMEOUT_SEC must be a positive integer" in result.stderr


def _run(tmp_path: Path, *, stub_body: str, timeout_sec: str) -> subprocess.CompletedProcess[str]:
    certbot = tmp_path / "certbot"
    certbot.write_text(f"#!/usr/bin/env bash\n{stub_body}\n")
    certbot.chmod(0o755)
    domains = tmp_path / "certbot-domains"
    domains.write_text("app.example.com\n")
    credentials = tmp_path / "cloudflare.ini"
    credentials.write_text("dns_cloudflare_api_token=placeholder\n")
    env = {
        **os.environ,
        "CERTBOT": str(certbot),
        "CERTBOT_DOMAINS_FILE": str(domains),
        "CERTBOT_TIMEOUT_SEC": timeout_sec,
        "CLOUDFLARE_CREDENTIALS": str(credentials),
        "CONF_DIR": str(tmp_path / "conf"),
        "HOME_WARDEN_RELOAD": "0",
        "HOME_WARDEN_SKIP_HOST_GUARD": "1",
        "SCRATCH_DIR": str(tmp_path / "scratch"),
        "SERVICE_GROUP": "",
    }
    return subprocess.run(
        [str(CERT_RENEWER), "--dry-run"],
        capture_output=True,
        env=env,
        text=True,
        timeout=90,
    )
