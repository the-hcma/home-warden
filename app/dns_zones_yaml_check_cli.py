"""One-shot CLI for dns_tinydns_convert.validate_zones_yaml_syntax:
`dns-zones-yaml-check` (see pyproject.toml [project.scripts]).

Usage:
  dns-zones-yaml-check [--list-zones] path/to/zones.yml

`--list-zones` prints each zone apex on its own stdout line (and the OK
line on stderr), so scripts/pdns-test-and-reload gets the zones to
reload in the recursor from the same run as its gate (#127).

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
    parser.add_argument(
        "--list-zones",
        action="store_true",
        help="print each zone apex on stdout (the OK line goes to stderr)",
    )
    parser.add_argument("zones_yaml", type=Path, help="zones.yml file to check")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        data = validate_zones_yaml_syntax(args.zones_yaml)
    except ValueError as e:
        print(f"dns-zones-yaml-check: {e}", file=sys.stderr)
        return 2
    if not args.list_zones:
        print(f"dns-zones-yaml-check: {args.zones_yaml}: OK")
        return 0
    print(f"dns-zones-yaml-check: {args.zones_yaml}: OK", file=sys.stderr)
    for entry in data["domains"]:
        print(entry["domain"].rstrip("."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
