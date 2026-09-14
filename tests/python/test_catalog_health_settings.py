"""Tests for app.catalog_health_settings, in particular the host-guard
bridge -- every consumer test patches `enforce_host_guard` at its call
site, so this module is the only place that actually exercises the real
subprocess/shell bridge to scripts/lib/host-guard.
"""

from __future__ import annotations

import subprocess
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


def test_enforce_host_guard_succeeds_with_matching_pin(monkeypatch, tmp_path: Path) -> None:
    # A pin file naming *this* host must let the real bridge succeed --
    # otherwise both fail-closed tests could pass even if
    # hw_host_guard_enforce/hw_matches_pinned_host silently always
    # returned false (the "success" path would never actually be
    # exercised). Queries the real short hostname the same way
    # scripts/lib/host-guard itself does, rather than hardcoding it.
    monkeypatch.delenv("HOME_WARDEN_SKIP_HOST_GUARD", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    config_dir = tmp_path / ".config"
    config_dir.mkdir()
    current_host = subprocess.run(
        ["hostname", "-s"], capture_output=True, text=True, timeout=5, check=True
    ).stdout.strip()
    (config_dir / "home-warden-host").write_text(current_host + "\n")
    assert enforce_host_guard("test") is True
