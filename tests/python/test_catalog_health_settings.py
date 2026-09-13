"""Tests for app.catalog_health_settings, in particular the host-guard
bridge -- every consumer test patches `enforce_host_guard` at its call
site, so this module is the only place that actually exercises the real
subprocess/shell bridge to scripts/lib/host-guard.
"""

from __future__ import annotations

from pathlib import Path

from app.catalog_health_settings import enforce_host_guard


def test_enforce_host_guard_skip_env_short_circuits(monkeypatch) -> None:
    monkeypatch.setenv("HOME_WARDEN_SKIP_HOST_GUARD", "1")
    assert enforce_host_guard("test") is True


def test_enforce_host_guard_fail_closed_with_no_pin(monkeypatch, tmp_path: Path) -> None:
    # No pin files under $HOME/.config -- host-guard must fail closed
    # (refuse), matching scripts/lib/host-guard's documented behavior.
    monkeypatch.delenv("HOME_WARDEN_SKIP_HOST_GUARD", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".config").mkdir()
    assert enforce_host_guard("test") is False
