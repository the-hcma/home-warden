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


def _tree(root: Path) -> dict[str, bytes | None]:
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def test_dry_run_leaves_an_incomplete_lineage_untouched(tmp_path: Path) -> None:
    """#199: files under live/archive but no renewal config (certs copied onto a new host) used to be moved
    aside by --dry-run before certbot ran. A dry run must change nothing under the certs directory."""
    certs = tmp_path / "conf" / "certs"
    (certs / "live" / "app.example.com").mkdir(parents=True)
    (certs / "live" / "app.example.com" / "fullchain.pem").write_text("cert")
    (certs / "archive" / "app.example.com").mkdir(parents=True)
    (certs / "archive" / "app.example.com" / "fullchain1.pem").write_text("cert")
    before = _tree(certs)

    result = _run(tmp_path, stub_body='echo "$@" >>"$(dirname "$0")/args"', timeout_sec="5")

    assert result.returncode == 0, result.stderr
    assert _tree(certs) == before
    assert not (tmp_path / "scratch" / "certs-staging-backup").exists()
    assert "incomplete lineage" in result.stdout and "Leaving it untouched" in result.stdout
    assert not (tmp_path / "args").exists()  # certbot isn't asked to certonly against a half-present lineage


def test_dry_run_still_checks_a_domain_with_no_lineage(tmp_path: Path) -> None:
    result = _run(tmp_path, stub_body='echo "$@" >"$(dirname "$0")/args"', timeout_sec="5")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "args").read_text().startswith("certonly -d app.example.com ")


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
