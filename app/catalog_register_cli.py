"""One-shot CLI for catalog_register: `catalog-register` (see pyproject.toml
[project.scripts]) / `uv run python -m app.catalog_register_cli`.

Usage:
  catalog-register --service my-service --target 203.0.113.10
  catalog-register --service my-service --target 203.0.113.10 --apply

Confirm-first: without --apply, every step previews what it would do
without changing anything (matches app.catalog_checks.sync_dns_record's
own dry_run) -- review the plan, then re-run with --apply.

Exit: 0 all steps ok/skipped/applied, 1 any step failed, 2 usage/config error.

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
from app.catalog_health_settings import (
    cert_renewer_path,
    certbot_domains_path,
    cloudflare_credentials_path,
    dns_sync_target,
    enforce_host_guard,
    local_pdns_port,
    max_retries,
    services_json_path,
    timeout_seconds,
)
from app.catalog_register import register_service


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Drive local DNS, external DNS, cert, and nginx validation for one catalog service."
    )
    parser.add_argument("--service", required=True, help="Catalog service name (must already exist in services.json)")
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--cloudflare-credentials", type=Path, default=cloudflare_credentials_path())
    parser.add_argument(
        "--target",
        default=dns_sync_target(),
        help="IP or hostname the external DNS record should point at (default: $DNS_SYNC_TARGET)",
    )
    parser.add_argument("--certbot-domains-file", type=Path, default=certbot_domains_path())
    parser.add_argument("--cert-renewer", type=Path, default=cert_renewer_path())
    parser.add_argument("--local-dns-port", type=int, default=local_pdns_port())
    parser.add_argument("--timeout", type=float, default=timeout_seconds())
    parser.add_argument("--max-retries", type=int, default=max_retries())
    parser.add_argument("--cert-timeout", type=float, default=600.0)
    parser.add_argument("--proxied", action="store_true", help="Enable Cloudflare proxy (orange-cloud)")
    parser.add_argument("--apply", action="store_true", help="Actually apply changes (default: preview only)")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def main() -> int:
    try:
        args = build_arg_parser().parse_args()
    except ValueError as e:
        print(f"catalog-register: {e}", file=sys.stderr)
        return 2

    if not args.target:
        print("catalog-register: --target is required (or set DNS_SYNC_TARGET)", file=sys.stderr)
        return 2

    if args.timeout <= 0:
        print(f"catalog-register: --timeout must be positive, got {args.timeout}", file=sys.stderr)
        return 2

    if not (1 <= args.local_dns_port <= 65535):
        print(
            f"catalog-register: --local-dns-port must be between 1 and 65535, got {args.local_dns_port}",
            file=sys.stderr,
        )
        return 2

    if not enforce_host_guard("catalog-register"):
        return 2

    try:
        catalog = load_catalog(args.services_json)
        cf_headers = parse_cloudflare_credentials(args.cloudflare_credentials)
    except (FileNotFoundError, ValueError) as e:
        print(f"catalog-register: {e}", file=sys.stderr)
        return 2

    if cf_headers is None:
        print(f"catalog-register: no Cloudflare credentials at {args.cloudflare_credentials}", file=sys.stderr)
        return 2

    results = register_service(
        args.service,
        catalog,
        dns_target=args.target,
        cf_headers=cf_headers,
        cloudflare_credentials=args.cloudflare_credentials,
        certbot_domains_file=args.certbot_domains_file,
        cert_renewer=args.cert_renewer,
        services_json_path=args.services_json,
        local_dns_port=args.local_dns_port,
        timeout=args.timeout,
        max_retries=args.max_retries,
        apply=args.apply,
        proxied=args.proxied,
        cert_timeout=args.cert_timeout,
    )

    if args.verbose:
        for r in results:
            print(f"{r.status:14} {r.step:14} {r.detail}", file=sys.stderr)

    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if any(r.status == "failed" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
