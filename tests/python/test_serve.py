"""Tests for config.serve's pure address-resolution logic (no real bind/listen)."""

from __future__ import annotations

import argparse

from config.serve import DEFAULT_PORT, build_arg_parser, resolve_listen_address


def _args(**overrides) -> argparse.Namespace:
    ns = build_arg_parser().parse_args([])
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_default_bind_is_loopback_and_default_port() -> None:
    host, port = resolve_listen_address(_args(), env={})
    assert host == "127.0.0.1"
    assert port == DEFAULT_PORT


def test_cli_flag_wins_over_env() -> None:
    host, port = resolve_listen_address(
        _args(listen_host="0.0.0.0", listen_port=9999),
        env={"HOME_WARDEN_LISTEN_HOST": "10.0.0.1", "HOME_WARDEN_LISTEN_PORT": "1234"},
    )
    assert (host, port) == ("0.0.0.0", 9999)


def test_env_used_when_no_cli_flag() -> None:
    env = {"HOME_WARDEN_LISTEN_HOST": "10.0.0.1", "HOME_WARDEN_LISTEN_PORT": "1234"}
    host, port = resolve_listen_address(_args(), env=env)
    assert (host, port) == ("10.0.0.1", 1234)


def test_invalid_port_raises() -> None:
    import pytest

    with pytest.raises(SystemExit):
        resolve_listen_address(_args(listen_port=70000), env={})
