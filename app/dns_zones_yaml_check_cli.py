"""One-shot CLI for dns_tinydns_convert.validate_zones_yaml_syntax:
`dns-zones-yaml-check` (see pyproject.toml [project.scripts]).

Usage:
  dns-zones-yaml-check path/to/zones.yml

Exit: 0 well-formed, 2 missing/malformed file.

Lightweight, offline syntax/shape check only -- no live pdns_server
involved. Intended as the pre-reload gate scripts/pdns-test-and-reload
runs before every `pdns_control reload`; see
app.dns_zone_validate.validate_via_sqlite_backend (local dev/CI) and
.github/ci/dns-catalog-validate (the real GeoIP-backend acceptance test)
for the deeper checks this does not replace.

Read-only and offline -- like render-catalog, this never touches live
infra, so it does not need scripts/lib/host-guard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.dns_tinydns_convert import validate_zones_yaml_syntax


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check a PowerDNS GeoIP-backend zones.yml for well-formedness.")
    parser.add_argument("zones_yaml", type=Path, help="zones.yml file to check")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        validate_zones_yaml_syntax(args.zones_yaml)
    except ValueError as e:
        print(f"dns-zones-yaml-check: {e}", file=sys.stderr)
        return 2
    print(f"dns-zones-yaml-check: {args.zones_yaml}: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
