"""One-shot CLI for dns_tinydns_convert: `dns-tinydns-convert` (see
pyproject.toml [project.scripts]) / `uv run python -m app.dns_tinydns_convert_cli`.

Usage:
  dns-tinydns-convert path/to/dns/data
  dns-tinydns-convert path/to/dns/data --outdir /stash/dns

Writes <outdir>/zones.yml and <outdir>/pdns.conf (default outdir: `.`),
per the-hcma/home#16's already-designed shape -- see that issue and
the-hcma/home-warden#108.

Exit: 0 converted ok, 2 usage/input error.

Read-only and offline (only reads the input file and writes local output
files) -- like render-catalog, this never touches live infra, so it does
not need scripts/lib/host-guard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.dns_tinydns_convert import (
    bucket_into_zones,
    parse_tinydns_data,
    render_pdns_conf,
    render_zones_yaml,
    zone_apexes_from_records,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert tinydns-format zone data into PowerDNS GeoIP-backend zones.yml + pdns.conf."
    )
    parser.add_argument("data_file", type=Path, help="tinydns-format data file to convert")
    parser.add_argument("--outdir", type=Path, default=Path("."), help="default: current directory")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    if not args.data_file.is_file():
        print(f"dns-tinydns-convert: missing input file: {args.data_file}", file=sys.stderr)
        return 2

    try:
        text = args.data_file.read_text()
        records = parse_tinydns_data(text)
        apexes = zone_apexes_from_records(records)
        if not apexes:
            print(f"dns-tinydns-convert: {args.data_file} defines no zones (no 'Z' SOA lines)", file=sys.stderr)
            return 2
        zones = bucket_into_zones(records, apexes)
    except ValueError as e:
        print(f"dns-tinydns-convert: {args.data_file}: {e}", file=sys.stderr)
        return 2

    args.outdir.mkdir(parents=True, exist_ok=True)
    zones_yaml_path = args.outdir / "zones.yml"
    pdns_conf_path = args.outdir / "pdns.conf"
    zones_yaml_path.write_text(render_zones_yaml(zones))
    pdns_conf_path.write_text(render_pdns_conf(str(zones_yaml_path.resolve())))

    print(f"dns-tinydns-convert: wrote {zones_yaml_path} and {pdns_conf_path} ({len(zones)} zone(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
