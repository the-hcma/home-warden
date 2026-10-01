"""`cutover-preflight` (see pyproject.toml [project.scripts]): can this host take over the front door? (#187)

Usage:
  cutover-preflight [--certbot-dry-run] [--no-sudo] [--quiet]

Read-only. `--certbot-dry-run` adds `cert-renewer --dry-run`, which needs a pinned host and talks to Let's
Encrypt staging (see app.cutover_preflight). Reads the served conf from $HOME_NGINX_CONF
(default ~/home/nginx/server/nginx.conf), the catalog from $SERVICES_JSON_PATH, and the same conf/ paths the
other tools use. Prints ok/WARN/FAIL per check, each failure with what to fix.

Exit: 0 no failures (warnings allowed), 1 any failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from app.catalog_checks import load_catalog
from app.catalog_health_settings import (
    REPO_ROOT,
    certbot_domains_path,
    client_pki_store,
    cloudflare_credentials_path,
    scratch_dir,
    services_json_path,
)
from app.cutover_preflight import Context, run_preflight
from app.home_warden_auth import session_secret_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only readiness check for a host taking over the front door.")
    parser.add_argument(
        "--certbot-dry-run",
        action="store_true",
        help="also run cert-renewer --dry-run (needs a pinned host; talks to Let's Encrypt staging; changes nothing)",
    )
    parser.add_argument("--no-sudo", action="store_true", help="run nginx -T without sudo")
    parser.add_argument("--quiet", "-q", action="store_true", help="only print warnings and failures")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    services = services_json_path()
    try:
        catalog = load_catalog(services)
    except (FileNotFoundError, ValueError):
        catalog = {}
    ctx = Context(
        nginx_conf=Path(
            os.environ.get("HOME_NGINX_CONF", str(Path.home() / "home" / "nginx" / "server" / "nginx.conf"))
        ),
        repo_dir=REPO_ROOT,
        certbot_domains=certbot_domains_path(),
        cloudflare_credentials=cloudflare_credentials_path(),
        session_secret=session_secret_path(),
        pki_store=client_pki_store(),
        use_sudo=not args.no_sudo,
        certbot=os.environ.get("CERTBOT", "/usr/bin/certbot"),
        certbot_dry_run=args.certbot_dry_run,
        scratch_dir=scratch_dir(),
        catalog=catalog,
    )
    results = run_preflight(ctx)
    failed = 0
    for r in results:
        if r.status == "fail":
            failed += 1
        if args.quiet and r.status == "ok":
            continue
        label = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}[r.status]
        print(f"{label} {r.name}: {r.detail}")
    warned = sum(r.status == "warn" for r in results)
    print(f"cutover-preflight: {len(results)} checks, {failed} failed, {warned} warnings", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
