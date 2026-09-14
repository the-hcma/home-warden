"""Run home-warden's HTTP API (FastAPI + uvicorn).

Currently exposes only GET /health/catalog (the-hcma/home-warden#57); the
future web UI (#55) is expected to grow this the way its consumers need,
not to gain its own second process.

Default bind: 127.0.0.1:8090 -- loopback-only until an operator explicitly
opts into something else via --listen-host/--listen-port or the
HOME_WARDEN_LISTEN_HOST/HOME_WARDEN_LISTEN_PORT env vars (e.g. once this
runs under its own systemd unit).
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from app.api.app import create_app

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
    return host, port


def main() -> None:
    args = build_arg_parser().parse_args()
    host, port = resolve_listen_address(args)
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
