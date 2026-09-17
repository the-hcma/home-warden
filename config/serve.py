"""Run home-warden's HTTP API (FastAPI + uvicorn).

Exposes the catalog health route plus the authenticated web UI. nginx remains
this service's only supported TLS/public entrypoint, so the backend binds
loopback-only even when operators pass explicit CLI/env overrides.
"""

from __future__ import annotations

import argparse
import ipaddress
import os

import uvicorn

from app.api.app import create_app
from app.home_warden_config import BACKEND_LOOPBACK_HOST

DEFAULT_PORT = 8090


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start home-warden's HTTP API.")
    parser.add_argument("--listen-host", default=None, metavar="ADDR")
    parser.add_argument("--listen-port", type=int, default=None, metavar="PORT")
    return parser


def resolve_listen_address(args: argparse.Namespace, *, env: dict[str, str] | None = None) -> tuple[str, int]:
    env = env if env is not None else dict(os.environ)
    host = args.listen_host or env.get("HOME_WARDEN_LISTEN_HOST") or "127.0.0.1"
    port_raw = args.listen_port if args.listen_port is not None else env.get("HOME_WARDEN_LISTEN_PORT")
    if port_raw in (None, ""):
        port = DEFAULT_PORT
    elif isinstance(port_raw, int):
        port = port_raw  # already validated by argparse's type=int
    else:
        try:
            port = int(port_raw)
        except ValueError as exc:
            raise SystemExit(f"home-warden-server: invalid HOME_WARDEN_LISTEN_PORT={port_raw!r}") from exc
    if not 0 <= port <= 65535:
        raise SystemExit(f"home-warden-server: --listen-port out of range (0..65535): {port}")
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise SystemExit(f"home-warden-server: --listen-host must be loopback-only, got {host!r}")
        except ValueError as exc:
            raise SystemExit(f"home-warden-server: --listen-host must be loopback-only, got {host!r}") from exc
    return host, port


def main() -> None:
    args = build_arg_parser().parse_args()
    host, port = resolve_listen_address(args)
    # proxy_headers/forwarded_allow_ips already default to this exact
    # setting (uvicorn.Config), but the login rate limiter (home-warden#82)
    # keys per-source-IP from the X-Forwarded-For this trusts, so the trust
    # boundary is spelled out here explicitly rather than left to an
    # implicit vendor default a future uvicorn upgrade could silently
    # change. BACKEND_LOOPBACK_HOST is the address the self-catalog vhost's
    # proxy_pass always targets (app/home_warden_config.py), so it's also
    # the only peer address a forwarded header can legitimately arrive
    # from -- trusting anything wider would let a non-nginx source on this
    # host spoof the header and bypass or hijack the per-IP throttle.
    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        proxy_headers=True,
        forwarded_allow_ips=BACKEND_LOOPBACK_HOST,
    )


if __name__ == "__main__":
    main()
