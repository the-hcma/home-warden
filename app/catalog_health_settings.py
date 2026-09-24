"""Env-driven settings + host-guard bridge shared by the CLI and the API route.

Mirrors scripts/cert-checker and scripts/cert-renewer's env var names so an
operator only has to learn one convention.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALLED_HOST_GUARD = Path("/usr/local/libexec/home-warden/host-guard")


def services_json_path() -> Path:
    return Path(os.environ.get("SERVICES_JSON_PATH", str(Path.home() / ".config" / "home-warden" / "services.json")))


def cert_renewer_path() -> Path:
    return Path(os.environ.get("CERT_RENEWER", str(REPO_ROOT / "scripts" / "cert-renewer")))


def certbot_domains_path() -> Path:
    """Mirrors scripts/cert-renewer's own CERTBOT_DOMAINS_FILE default --
    see #110's registration flow, which appends a newly-registered
    service's server_name here before invoking that script unchanged.
    """
    return Path(os.environ.get("CERTBOT_DOMAINS_FILE", str(REPO_ROOT / "conf" / "certbot-domains")))


def certs_live_dir() -> Path:
    conf_dir = Path(os.environ.get("CONF_DIR", str(Path.home() / "conf" / "home-warden")))
    return Path(os.environ.get("CERTS_LIVE_DIR", str(conf_dir / "certs" / "live")))


def cloudflare_credentials_path() -> Path:
    return Path(os.environ.get("CLOUDFLARE_CREDENTIALS", str(REPO_ROOT / "conf" / "cloudflare.ini")))


def dns_sync_target() -> str | None:
    """The IP/hostname every synced DNS record should point at -- no
    default, since every service shares this one value (home-warden fronts
    every public service from the one host); missing means the operator
    hasn't configured it yet, not a stale/wrong guess.
    """
    return os.environ.get("DNS_SYNC_TARGET")


def local_pdns_port() -> int:
    """Port the local PowerDNS authoritative server listens on (#108's
    render_pdns_conf emits local-port=853) -- overridable for local dev/CI
    against a differently-configured instance.
    """
    return int(os.environ.get("LOCAL_PDNS_PORT", "853"))


def pdns_zones_yaml_path() -> Path:
    """Mirrors scripts/setup-service's PDNS_ZONES_YAML resolution (#108)
    -- the thehcma/home dns/zones.yml checkout path the local PowerDNS
    zone reads. Same env var name and default (~/home/dns/zones.yml) as
    that script's own opt-in resolution, so one env var configures both.
    """
    return Path(os.environ.get("PDNS_ZONES_YAML", str(Path.home() / "home" / "dns" / "zones.yml")))


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
    host_guard = (
        INSTALLED_HOST_GUARD if INSTALLED_HOST_GUARD.is_file() else REPO_ROOT / "scripts" / "lib" / "host-guard"
    )
    proc = subprocess.run(
        ["bash", "-c", f'source "{host_guard}" && hw_host_guard_enforce "{caller}"'],
        timeout=5,
        check=False,
    )
    return proc.returncode == 0
