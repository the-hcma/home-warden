"""One-shot CLI for dns_tinydns_convert: `dns-tinydns-convert` (see
pyproject.toml [project.scripts]) / `uv run python -m app.dns_tinydns_convert_cli`.

Usage:
  dns-tinydns-convert path/to/dns/data
  dns-tinydns-convert path/to/dns/data --outdir /stash/dns

Writes <outdir>/zones.yml and <outdir>/pdns.conf (default outdir: `.`),
per the-hcma/home#16's already-designed shape -- see that issue and
the-hcma/home-warden#108.

Imports everything it can (#169): a line it can't parse, a record no
zone contains, or a zone whose SOA has no ttl is skipped rather than
failing the run, and the written zones.yml is then linted
(app.dns_zones_lint). Every one of those lands in a single warning block
at the end, each with its fix; the ones marked "blocks reload" must be
fixed before scripts/pdns-test-and-reload will serve the file.

Exit: 0 converted (with or without warnings), 2 usage/input error or
nothing convertible.

Read-only and offline (only reads the input file and writes local output
files) -- like render-catalog, this never touches live infra, so it does
not need scripts/lib/host-guard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from app.dns_tinydns_convert import (
    ParsedRecord,
    bucket_into_zones,
    parse_tinydns_data,
    render_pdns_conf,
    render_zones_yaml,
    zone_apexes_from_records,
)
from app.dns_zones_lint import ZoneIssue, format_issues, lint_zones


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

    issues: list[ZoneIssue] = []
    dropped: list[ParsedRecord] = []
    records = parse_tinydns_data(args.data_file.read_text(), issues)
    apexes = zone_apexes_from_records(records)
    zones = bucket_into_zones(records, apexes, dropped, issues) if apexes else {}
    issues.extend(
        ZoneIssue(
            rec.owner,
            f"the implicit PTR to {rec.content} was skipped: no Z line defines its reverse zone",
            "add a Z line for the reverse zone if this server should answer it; otherwise nothing to do",
        )
        for rec in dropped
    )
    if not zones:
        reason = "defines no zones (no 'Z' SOA lines)" if not apexes else "has no zone that could be converted"
        print(f"dns-tinydns-convert: {args.data_file} {reason}", file=sys.stderr)
        if issues:
            print(format_issues("dns-tinydns-convert", issues), file=sys.stderr)
        return 2

    zones_yaml_text = render_zones_yaml(zones, args.data_file.name)
    issues.extend(lint_zones(yaml.safe_load(zones_yaml_text)))

    args.outdir.mkdir(parents=True, exist_ok=True)
    zones_yaml_path = args.outdir / "zones.yml"
    pdns_conf_path = args.outdir / "pdns.conf"
    zones_yaml_path.write_text(zones_yaml_text)
    pdns_conf_path.write_text(render_pdns_conf(str(zones_yaml_path.resolve())))

    print(f"dns-tinydns-convert: wrote {zones_yaml_path} and {pdns_conf_path} ({len(zones)} zone(s))")
    if issues:
        note = f" in {args.data_file} (fixes use zones.yml terms; make them in whichever file you edit)"
        print(format_issues("dns-tinydns-convert", issues, note=note), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
