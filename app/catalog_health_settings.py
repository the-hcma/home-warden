"""Env-driven settings + host-guard bridge shared by the CLI and the API route.

Mirrors scripts/cert-checker and scripts/cert-renewer's env var names so an
operator only has to learn one convention.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def services_json_path() -> Path:
    return Path(os.environ.get("SERVICES_JSON_PATH", str(Path.home() / ".config" / "home-warden" / "services.json")))


def certs_live_dir() -> Path:
    conf_dir = Path(os.environ.get("CONF_DIR", str(Path.home() / "conf" / "home-warden")))
    return Path(os.environ.get("CERTS_LIVE_DIR", str(conf_dir / "certs" / "live")))


def cloudflare_credentials_path() -> Path:
    return Path(os.environ.get("CLOUDFLARE_CREDENTIALS", str(REPO_ROOT / "conf" / "cloudflare.ini")))


def alert_days() -> int:
    return int(os.environ.get("ALERT_DAYS", "10"))


def timeout_seconds() -> float:
    return float(os.environ.get("CATALOG_HEALTH_TIMEOUT_SEC", "5"))


def max_retries() -> int:
    return int(os.environ.get("CATALOG_HEALTH_MAX_RETRIES", "3"))


def enforce_host_guard(caller: str) -> bool:
    """Refuse to act anywhere but the host pinned by
    `scripts/setup-service --confirm-host` -- shells out to the existing
    Bash scripts/lib/host-guard so the pin logic has one source of truth
    instead of a second, Python-side reimplementation that could drift.
    """
    if os.environ.get("HOME_WARDEN_SKIP_HOST_GUARD") == "1":
        return True
    host_guard = REPO_ROOT / "scripts" / "lib" / "host-guard"
    proc = subprocess.run(
        ["bash", "-c", f'source "{host_guard}" && hw_host_guard_enforce "{caller}"'],
        timeout=5,
        check=False,
    )
    return proc.returncode == 0
