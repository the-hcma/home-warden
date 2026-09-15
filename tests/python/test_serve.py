"""Tests for config.serve's pure address-resolution logic (no real bind/listen)."""

from __future__ import annotations

import argparse

import pytest

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


def test_cli_flag_allows_loopback_alias() -> None:
    host, port = resolve_listen_address(
        _args(listen_host="localhost", listen_port=9999),
        env={"HOME_WARDEN_LISTEN_HOST": "127.0.0.1", "HOME_WARDEN_LISTEN_PORT": "1234"},
    )
    assert (host, port) == ("localhost", 9999)


def test_env_used_when_no_cli_flag() -> None:
    env = {"HOME_WARDEN_LISTEN_HOST": "127.0.0.1", "HOME_WARDEN_LISTEN_PORT": "1234"}
    host, port = resolve_listen_address(_args(), env=env)
    assert (host, port) == ("127.0.0.1", 1234)


def test_invalid_port_raises() -> None:
    with pytest.raises(SystemExit):
        resolve_listen_address(_args(listen_port=70000), env={})


def test_non_loopback_host_raises() -> None:
    with pytest.raises(SystemExit):
        resolve_listen_address(_args(listen_host="0.0.0.0"), env={})


def test_non_numeric_env_port_raises_systemexit_not_valueerror() -> None:
    # --listen-port goes through argparse's type=int (clean SystemExit on
    # bad input); the env var path used to reach a bare int() and escape
    # as an uncaught ValueError instead of the same clean SystemExit.
    with pytest.raises(SystemExit):
        resolve_listen_address(_args(), env={"HOME_WARDEN_LISTEN_PORT": "809O"})
