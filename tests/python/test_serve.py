"""Tests for config.serve's pure address-resolution logic (no real bind/listen)."""

from __future__ import annotations

import argparse

import pytest

import config.serve as serve
from app.home_warden_config import BACKEND_LOOPBACK_HOST
from config.serve import DEFAULT_PORT, build_arg_parser, main, resolve_listen_address


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


def test_main_trusts_forwarded_headers_only_from_the_backend_loopback_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # home-warden#82: the login rate limiter keys per-source-IP from
    # X-Forwarded-For, so this pins the trust boundary explicitly rather
    # than relying on it matching uvicorn's own default forever. Widening
    # forwarded_allow_ips beyond the one peer nginx's proxy_pass actually
    # connects from would let any other loopback process spoof the header
    # and bypass or hijack the per-IP throttle.
    captured: dict[str, object] = {}

    def _fake_run(app: object, **kwargs: object) -> None:
        del app
        captured.update(kwargs)

    monkeypatch.setattr(serve.uvicorn, "run", _fake_run)
    monkeypatch.setattr("sys.argv", ["home-warden-server"])
    monkeypatch.delenv("HOME_WARDEN_LISTEN_HOST", raising=False)
    monkeypatch.delenv("HOME_WARDEN_LISTEN_PORT", raising=False)

    main()

    assert captured["proxy_headers"] is True
    assert captured["forwarded_allow_ips"] == BACKEND_LOOPBACK_HOST == "127.0.0.1"
