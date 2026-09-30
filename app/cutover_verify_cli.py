"""`cutover-verify` (see pyproject.toml [project.scripts]): nginx parity between the current and a replacement
host, vhost by vhost, with no DNS change (#188).

Usage:
  cutover-verify --old 192.0.2.10 --new 198.51.100.10 [--old6 ... --new6 ...]
  cutover-verify --old A --new B --host extra.example.com --client-cert t.crt --client-key t.key

Vhosts come from the catalog's `server_name`s (plus `--host NAME`, repeatable). Catalog entries with
`websocket: true` also get an Upgrade probe. `--client-cert/--client-key` (a throwaway test cert from
`scripts/client-pki`) adds an mTLS probe: run it again with a revoked cert to check revocation took
effect on both. After the cutover, pass the same address twice or the public address as `--new` as a smoke test.

Exit: 0 no differences, 1 any difference or an address that couldn't be reached (even if both can't),
2 usage/config error (including an unusable client cert). The `ok` line shows the new side's status codes:
after a cutover, read them, since identical 502s on both sides still compare equal.
Read-only; needs no host guard.
"""

from __future__ import annotations

import argparse
import ssl
import sys
from pathlib import Path

from app.catalog_checks import load_catalog
from app.catalog_health_settings import services_json_path, timeout_seconds
from app.cutover_verify import compare, probe_vhost


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare what two hosts serve for each catalog vhost.")
    parser.add_argument("--old", required=True, help="current host IPv4 address")
    parser.add_argument("--new", required=True, help="replacement host IPv4 address")
    parser.add_argument("--old6", help="current host IPv6 address")
    parser.add_argument("--new6", help="replacement host IPv6 address")
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--host", action="append", default=[], help="extra vhost name not in the catalog")
    parser.add_argument("--client-cert", type=Path)
    parser.add_argument("--client-key", type=Path)
    parser.add_argument("--timeout", type=float, default=min(timeout_seconds(), 5.0))
    parser.add_argument("--quiet", "-q", action="store_true", help="only print differences")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    if bool(args.old6) != bool(args.new6):
        print("cutover-verify: --old6 and --new6 go together", file=sys.stderr)
        return 2
    if bool(args.client_cert) != bool(args.client_key):
        print("cutover-verify: --client-cert and --client-key go together", file=sys.stderr)
        return 2
    if args.client_cert:
        try:
            ssl.create_default_context().load_cert_chain(args.client_cert, args.client_key)
        except (OSError, ssl.SSLError) as e:
            print(f"cutover-verify: unusable --client-cert/--client-key: {e}", file=sys.stderr)
            return 2
    try:
        catalog = load_catalog(args.services_json)
    except (FileNotFoundError, ValueError) as e:
        if not args.host:
            print(f"cutover-verify: {e} (and no --host given)", file=sys.stderr)
            return 2
        print(f"cutover-verify: WARNING: catalog not used ({e}); checking only the --host names", file=sys.stderr)
        catalog = {"services": []}

    vhosts: dict[str, bool] = {}  # name -> websocket
    for s in catalog.get("services") or []:
        if s.get("server_name"):
            vhosts[s["server_name"]] = bool(s.get("websocket"))
    for h in args.host:
        vhosts.setdefault(h, False)
    if not vhosts:
        print("cutover-verify: no vhosts (empty catalog and no --host)", file=sys.stderr)
        return 2

    client = (str(args.client_cert), str(args.client_key)) if args.client_cert else None
    pairs = [("v4", args.old, args.new)]
    if args.old6:
        pairs.append(("v6", args.old6, args.new6))

    bad = 0
    for name, ws in sorted(vhosts.items()):
        for label, old_addr, new_addr in pairs:
            old = probe_vhost(name, old_addr, timeout=args.timeout, client_cert=client, websocket=ws)
            new = probe_vhost(name, new_addr, timeout=args.timeout, client_cert=client, websocket=ws)
            diffs = compare(old, new)
            if diffs:
                bad += 1
                print(f"DIFF {label} {name}")
                for d in diffs:
                    print(f"     {d}")
            elif not args.quiet:
                seen = f"http={new.facts.get('http.status')} https={new.facts.get('https.status')}"
                print(f"ok   {label} {name}  ({seen}, cert notAfter {new.info.get('tls.notAfter')})")
    print(f"cutover-verify: {len(vhosts)} vhosts, {bad} with differences", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
