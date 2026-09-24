"""One-shot CLI for catalog-checks: `catalog-health-check` (see pyproject.toml
[project.scripts]) / `uv run python -m app.catalog_health_cli`.

Usage:
  catalog-health-check
  catalog-health-check --verbose
  catalog-health-check --skip-dns --skip-upstream

Exit: 0 all checks ok/skipped, 1 any check failed, 2 usage/config error.

Refuses to run anywhere but the host pinned by
`scripts/setup-service --confirm-host` (see scripts/lib/host-guard).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from app.catalog_checks import load_catalog, parse_cloudflare_credentials, run_all
from app.catalog_health_settings import (
    alert_days,
    certs_live_dir,
    cloudflare_credentials_path,
    enforce_host_guard,
    local_pdns_port,
    max_retries,
    services_json_path,
    timeout_seconds,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a home-warden service catalog's cert/DNS/local-DNS/internal-upstream health."
    )
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--certs-live-dir", type=Path, default=certs_live_dir())
    parser.add_argument("--alert-days", type=int, default=alert_days())
    parser.add_argument("--cloudflare-credentials", type=Path, default=cloudflare_credentials_path())
    parser.add_argument("--local-dns-port", type=int, default=local_pdns_port())
    parser.add_argument("--timeout", type=float, default=timeout_seconds())
    parser.add_argument("--max-retries", type=int, default=max_retries())
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--skip-cert", action="store_true")
    parser.add_argument("--skip-dns", action="store_true")
    parser.add_argument("--skip-local-dns", action="store_true")
    parser.add_argument("--skip-upstream", action="store_true")
    return parser


def main() -> int:
    # One error boundary for config resolution (argparse defaults call
    # app.catalog_health_settings' env getters, e.g. ALERT_DAYS=ten ->
    # int() raises here, before argparse itself even runs) and a second
    # for the load-and-check flow (load_catalog, parse_cloudflare_credentials,
    # run_all) -- deliberately just these two, not one try per call, so the
    # exit-2 "usage/config error" contract is decided once for this whole
    # module rather than re-litigated call-by-call as new callers are added.
    try:
        args = build_arg_parser().parse_args()
    except ValueError as e:
        print(f"catalog-health-check: {e}", file=sys.stderr)
        return 2

    if not enforce_host_guard("catalog-health-check"):
        return 2

    try:
        catalog = load_catalog(args.services_json)
        cf_headers = None
        if not args.skip_dns:
            cf_headers = parse_cloudflare_credentials(args.cloudflare_credentials)
        results = run_all(
            catalog,
            certs_live_dir=args.certs_live_dir,
            alert_days=args.alert_days,
            cf_headers=cf_headers,
            local_dns_port=args.local_dns_port,
            timeout=args.timeout,
            max_retries=args.max_retries,
            skip_cert=args.skip_cert,
            skip_dns=args.skip_dns,
            skip_local_dns=args.skip_local_dns,
            skip_upstream=args.skip_upstream,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"catalog-health-check: {e}", file=sys.stderr)
        return 2

    if args.verbose:
        for r in results:
            marker = {"ok": "OK", "fail": "FAIL", "skip": "SKIP"}[r.status]
            print(f"{marker:4} {r.service:24} {r.dimension:9} {r.detail}", file=sys.stderr)

    print(json.dumps([asdict(r) for r in results], indent=2))
    return 1 if any(r.status == "fail" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
