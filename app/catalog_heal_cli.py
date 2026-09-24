"""One-shot CLI for catalog_heal: `catalog-heal` (see pyproject.toml
[project.scripts]) / `uv run python -m app.catalog_heal_cli`.

Usage:
  catalog-heal --target 203.0.113.10
  catalog-heal --target 203.0.113.10 --apply

Confirm-first: without --apply, every dimension previews what it would do
without changing anything, sending mail, or touching flap-protection
state (matches app.catalog_register's own contract) -- review the plan,
then re-run with --apply. The systemd timer (see AGENTS.md's Catalog
Auto-Healing section) always passes --apply.

Exit: 0 nothing needs attention, 1 something failed/alert-only/cooling
down, 2 usage/config error.

Refuses to run anywhere but the host pinned by
`scripts/setup-service --confirm-host` (see scripts/lib/host-guard).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from app.catalog_checks import load_catalog, parse_cloudflare_credentials
from app.catalog_heal import heal_catalog
from app.catalog_health_settings import (
    alert_days,
    cert_renewer_path,
    certbot_domains_path,
    certs_live_dir,
    cloudflare_credentials_path,
    dns_sync_target,
    enforce_host_guard,
    heal_alert_resend_seconds,
    heal_alert_to,
    heal_attempt_window_seconds,
    heal_cooldown_seconds,
    heal_max_attempts_per_window,
    heal_state_path,
    local_pdns_port,
    max_retries,
    services_json_path,
    timeout_seconds,
)
from app.smtp_config import load_smtp_config

_NEEDS_ATTENTION = frozenset({"alert-only", "cooldown", "failed"})


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect and heal cert/external-DNS drift across the catalog; alert on local-DNS/upstream drift."
    )
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--certs-live-dir", type=Path, default=certs_live_dir())
    parser.add_argument("--alert-days", type=int, default=alert_days())
    parser.add_argument("--cloudflare-credentials", type=Path, default=cloudflare_credentials_path())
    parser.add_argument(
        "--target",
        default=dns_sync_target(),
        help="IP or hostname a healed external DNS record should point at (default: $DNS_SYNC_TARGET)",
    )
    parser.add_argument("--certbot-domains-file", type=Path, default=certbot_domains_path())
    parser.add_argument("--cert-renewer", type=Path, default=cert_renewer_path())
    parser.add_argument("--local-dns-port", type=int, default=local_pdns_port())
    parser.add_argument("--timeout", type=float, default=timeout_seconds())
    parser.add_argument("--max-retries", type=int, default=max_retries())
    parser.add_argument("--cert-timeout", type=float, default=600.0)
    parser.add_argument("--proxied", action="store_true", help="Enable Cloudflare proxy (orange-cloud) on heal")
    parser.add_argument("--state-file", type=Path, default=heal_state_path())
    parser.add_argument("--cooldown-sec", type=float, default=heal_cooldown_seconds())
    parser.add_argument("--max-attempts", type=int, default=heal_max_attempts_per_window())
    parser.add_argument("--attempt-window-sec", type=float, default=heal_attempt_window_seconds())
    parser.add_argument("--resend-sec", type=float, default=heal_alert_resend_seconds())
    parser.add_argument("--alert-to", default=heal_alert_to())
    parser.add_argument("--apply", action="store_true", help="Actually heal/alert (default: preview only)")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def main() -> int:
    try:
        args = build_arg_parser().parse_args()
    except ValueError as e:
        print(f"catalog-heal: {e}", file=sys.stderr)
        return 2

    if args.timeout <= 0:
        print(f"catalog-heal: --timeout must be positive, got {args.timeout}", file=sys.stderr)
        return 2

    if not (1 <= args.local_dns_port <= 65535):
        print(f"catalog-heal: --local-dns-port must be between 1 and 65535, got {args.local_dns_port}", file=sys.stderr)
        return 2

    if not enforce_host_guard("catalog-heal"):
        return 2

    try:
        catalog = load_catalog(args.services_json)
        cf_headers = parse_cloudflare_credentials(args.cloudflare_credentials)
    except (FileNotFoundError, ValueError) as e:
        print(f"catalog-heal: {e}", file=sys.stderr)
        return 2

    results = heal_catalog(
        catalog,
        certs_live_dir=args.certs_live_dir,
        alert_days=args.alert_days,
        cf_headers=cf_headers,
        dns_target=args.target,
        local_dns_port=args.local_dns_port,
        timeout=args.timeout,
        max_retries=args.max_retries,
        apply=args.apply,
        proxied=args.proxied,
        cloudflare_credentials=args.cloudflare_credentials,
        certbot_domains_file=args.certbot_domains_file,
        cert_renewer=args.cert_renewer,
        cert_timeout=args.cert_timeout,
        state_path=args.state_file,
        cooldown_seconds=args.cooldown_sec,
        max_attempts_per_window=args.max_attempts,
        attempt_window_seconds=args.attempt_window_sec,
        resend_seconds=args.resend_sec,
        smtp_config=load_smtp_config(),
        alert_to=args.alert_to,
    )

    if args.verbose:
        for r in results:
            print(f"{r.action:11} {r.service:24} {r.dimension:9} {r.detail}", file=sys.stderr)

    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if any(r.action in _NEEDS_ATTENTION for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
