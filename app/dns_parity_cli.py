"""`dns-parity` (see pyproject.toml [project.scripts]): compare two DNS servers' answers for every record in
a zones.yml (#189).

Usage:
  dns-parity --old 192.0.2.53 --new 198.51.100.53 [--zones zones.yml]
  dns-parity --old 192.0.2.53 --new 127.0.0.1:853 --probe www.example.org --probe nope.example.com

`--old`/`--new` are `HOST`, `HOST:PORT`, `[V6]` or `[V6]:PORT` (port defaults to 53). Query the recursors
to check the path clients use, and the authoritative servers (loopback:853 on-host) for the record data.
`--probe NAME[/TYPE]` adds names that aren't in zones.yml (a public name that must forward, one that must
be NXDOMAIN); type defaults to A.

Exit: 0 no differences, 1 any difference, 2 usage/config error (including no `dig`).
Read-only; needs no host guard.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from app.catalog_health_settings import pdns_zones_yaml_path
from app.dns_parity import expected_queries, parse_server, run_parity
from app.dns_zones_view import load_zones_yaml


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare two DNS servers' answers for every record in zones.yml.")
    parser.add_argument("--old", required=True, help="the current server: HOST[:PORT]")
    parser.add_argument("--new", required=True, help="the replacement server: HOST[:PORT]")
    parser.add_argument(
        "--zones", type=Path, default=pdns_zones_yaml_path(), help="zones.yml (default: $PDNS_ZONES_YAML)"
    )
    parser.add_argument("--probe", action="append", default=[], metavar="NAME[/TYPE]")
    parser.add_argument("--timeout", type=int, default=3, help="per-query dig timeout in seconds")
    parser.add_argument("--quiet", "-q", action="store_true", help="only print differences")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    if shutil.which("dig") is None:
        print("dns-parity: dig not found (apt install bind9-dnsutils)", file=sys.stderr)
        return 2
    try:
        old, new = parse_server(args.old), parse_server(args.new)
    except ValueError as e:
        print(f"dns-parity: bad server address: {e}", file=sys.stderr)
        return 2
    zones = load_zones_yaml(args.zones)
    if not zones and not args.probe:
        print(f"dns-parity: no usable zones at {args.zones} and no --probe given", file=sys.stderr)
        return 2
    queries = expected_queries(zones)
    must_answer = frozenset(queries)
    for probe in args.probe:
        name, _, rtype = probe.partition("/")
        queries.append((name, (rtype or "A").upper()))

    findings = run_parity(queries, old, new, args.timeout, must_answer=must_answer)
    bad = 0
    for f in findings:
        if f.differences:
            bad += 1
            print(f"DIFF {f.name} {f.rtype}")
            for d in f.differences:
                print(f"     {d}")
        elif not args.quiet:
            print(f"ok   {f.name} {f.rtype}")
    print(f"dns-parity: {len(findings)} queries, {bad} with differences", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
