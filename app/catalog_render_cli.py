"""One-shot CLI for catalog_render: `render-catalog` (see pyproject.toml
[project.scripts]) / `uv run python -m app.catalog_render_cli`.

Usage:
  render-catalog
  render-catalog --output /tmp/rendered.conf
  render-catalog --services-json ./services.json.example --certs-live-dir /tmp/certs

Exit: 0 rendered ok, 2 usage/catalog/config error.

Read-only and offline: unlike catalog-health-check, this never touches
live cert/DNS/upstream state, so it does not need scripts/lib/host-guard --
render on any host, review the diff, and only an operator decides whether
to actually deploy generated output onto the service host.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.catalog_checks import load_catalog
from app.catalog_health_settings import certs_live_dir, services_json_path
from app.catalog_render import DEFAULT_CLIENT_MAX_BODY_SIZE, DEFAULT_SSL_PROTOCOLS, RenderContext, render_catalog


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a home-warden service catalog into nginx config.")
    parser.add_argument("--services-json", type=Path, default=services_json_path())
    parser.add_argument("--certs-live-dir", type=Path, default=certs_live_dir())
    parser.add_argument("--client-max-body-size", default=DEFAULT_CLIENT_MAX_BODY_SIZE)
    parser.add_argument("--ssl-protocols", default=DEFAULT_SSL_PROTOCOLS)
    parser.add_argument(
        "--no-server-tokens-off",
        dest="server_tokens_off",
        action="store_false",
        help="omit the default `server_tokens off;` (Gixy-Next version_disclosure fix)",
    )
    parser.add_argument("--output", "-o", type=Path, default=None, help="default: stdout")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    try:
        catalog = load_catalog(args.services_json)
        ctx = RenderContext(
            certs_live_dir=args.certs_live_dir,
            client_max_body_size=args.client_max_body_size,
            server_tokens_off=args.server_tokens_off,
            ssl_protocols=args.ssl_protocols,
        )
        rendered = render_catalog(catalog, ctx)
    except (FileNotFoundError, ValueError) as e:
        print(f"render-catalog: {e}", file=sys.stderr)
        return 2
    except (KeyError, TypeError) as e:
        # load_catalog only validates the top-level services list and each
        # entry's upstream object -- a catalog that's shape-valid JSON but
        # missing/misusing a field the renderer itself requires (no
        # server_name, static.root, an unknown client_cert.mode, a
        # streams entry with no upstream, ...) surfaces here as a raw
        # KeyError/TypeError instead of load_catalog's ValueError. Report
        # it the same way rather than let a traceback escape the
        # documented exit-2 contract.
        print(f"render-catalog: malformed catalog: {e!r}", file=sys.stderr)
        return 2

    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
