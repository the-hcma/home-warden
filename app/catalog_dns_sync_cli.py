"""One-shot CLI for DNS record sync: `catalog-dns-sync` (see pyproject.toml
[project.scripts]) / `uv run python -m app.catalog_dns_sync_cli`.

Usage:
  catalog-dns-sync --target 203.0.113.10
  catalog-dns-sync --target 203.0.113.10 --dry-run
  catalog-dns-sync --target 203.0.113.10 --service my-service

Exit: 0 all synced services created/updated/noop/skipped, 1 any sync
failed, 2 usage/config error.

Refuses to run anywhere but the host pinned by
`scripts/setup-service --confirm-host` (see scripts/lib/host-guard).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from app.catalog_checks import load_catalog, parse_cloudflare_credentials, sync_dns_record
from app.catalog_health_settings import (
    cloudflare_credentials_path,
    dns_sync_target,
    enforce_host_guard,
    max_retries,
    services_json_path,
    timeout_seconds,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create/update Cloudflare DNS records for catalog services.")
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--cloudflare-credentials", type=Path, default=cloudflare_credentials_path())
    parser.add_argument("--timeout", type=float, default=timeout_seconds())
    parser.add_argument("--max-retries", type=int, default=max_retries())
    parser.add_argument(
        "--target",
        default=dns_sync_target(),
        help="IP or hostname every synced record should point at (default: $DNS_SYNC_TARGET)",
    )
    parser.add_argument("--proxied", action="store_true", help="Enable Cloudflare proxy (orange-cloud)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--no-verify-resolution", action="store_true", help="Skip the authoritative-nameserver dig check"
    )
    parser.add_argument("--service", action="append", dest="services", help="Limit to this service name (repeatable)")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def main() -> int:
    # Same two-error-boundary shape as catalog_health_cli.main: config
    # resolution (argparse defaults calling the settings module's env
    # getters) first, then the load-and-sync flow -- one exit-2 contract
    # for the whole module rather than a try per call.
    try:
        args = build_arg_parser().parse_args()
    except ValueError as e:
        print(f"catalog-dns-sync: {e}", file=sys.stderr)
        return 2

    if not args.target:
        print("catalog-dns-sync: --target is required (or set DNS_SYNC_TARGET)", file=sys.stderr)
        return 2

    if not enforce_host_guard("catalog-dns-sync"):
        return 2

    try:
        catalog = load_catalog(args.services_json)
        cf_headers = parse_cloudflare_credentials(args.cloudflare_credentials)
    except (FileNotFoundError, ValueError) as e:
        print(f"catalog-dns-sync: {e}", file=sys.stderr)
        return 2

    if cf_headers is None:
        print(f"catalog-dns-sync: no Cloudflare credentials at {args.cloudflare_credentials}", file=sys.stderr)
        return 2

    services = catalog.get("services") or []
    if args.services:
        services = [s for s in services if s.get("name") in args.services]

    results = [
        sync_dns_record(
            s.get("name", "<unnamed>"),
            s,
            args.target,
            cf_headers,
            args.timeout,
            args.max_retries,
            proxied=args.proxied,
            dry_run=args.dry_run,
            verify_resolution=not args.no_verify_resolution,
        )
        for s in services
    ]

    if args.verbose:
        for r in results:
            print(f"{r.status:14} {r.service:24} {r.detail}", file=sys.stderr)

    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if any(r.status == "failed" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
