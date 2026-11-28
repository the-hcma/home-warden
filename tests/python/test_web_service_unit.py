"""The web UI backend's systemd unit and the setup-service wiring that enables it only when `fqdn` is set (#280)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from app.home_warden_config import BACKEND_LOOPBACK_HOST, BACKEND_LOOPBACK_PORT

REPO = Path(__file__).resolve().parents[2]


SETUP = REPO / "scripts" / "setup-service"


UNIT = REPO / "etc" / "systemd" / "home-warden-web.service"


def test_setup_service_installs_and_starts_the_unit_only_when_the_web_ui_is_enabled() -> None:
    text = SETUP.read_text()
    assert "web_ui_enabled=0" in text
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n\s+expand_unit .*home-warden-web\.service", text)
    assert re.search(
        r"if \(\(web_ui_enabled\)\); then\n\s+# .*\n\s+run sudo systemctl enable home-warden-web\.service", text
    )
    assert "run sudo systemctl restart home-warden-web.service" in text
    assert "run sudo systemctl disable --now home-warden-web.service" in text


def test_the_unit_does_not_set_no_new_privileges_because_the_pam_login_needs_the_setgid_helper() -> None:
    directives = [line for line in UNIT.read_text().splitlines() if not line.lstrip().startswith("#")]
    assert not any(line.startswith("NoNewPrivileges") for line in directives)


def test_the_unit_runs_the_loopback_backend_as_the_owner() -> None:
    text = UNIT.read_text()
    assert "User=@@OWNER@@" in text
    assert "ExecStart=@@REPO_DIR@@/scripts/catalog-health-server" in text
    assert f"HOME_WARDEN_LISTEN_HOST={BACKEND_LOOPBACK_HOST}" in text
    assert f"HOME_WARDEN_LISTEN_PORT={BACKEND_LOOPBACK_PORT}" in text
    assert "Restart=on-failure" in text
    assert "WantedBy=multi-user.target" in text


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ('fqdn = "warden.hcma.info"\n', "warden.hcma.info"),
        ('# web UI\nfqdn = "warden.hcma.info"  # public name\n', "warden.hcma.info"),
        ('fqdn="warden.hcma.info"', "warden.hcma.info"),
        ('fqdn = ""\n', ""),
        ('fqdn = "not a host"\n', ""),
        ('fqdn = "localhost"\n', ""),
        ("other = 1\n", ""),
        (None, ""),
    ],
)
def test_web_ui_fqdn_reads_a_valid_name_and_nothing_else(config, expected, tmp_path: Path) -> None:
    assert _web_ui_fqdn(config, tmp_path) == expected


def _bash_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SETUP.read_text(), re.S | re.M)
    assert match, f"{name} not found in setup-service"
    return match.group(0)


def _web_ui_fqdn(config_text: str | None, tmp_path: Path) -> str:
    config = tmp_path / "config.toml"
    if config_text is not None:
        config.write_text(config_text)
    functions = f"{_bash_function('is_valid_fqdn')}\n{_bash_function('web_ui_fqdn')}"
    script = f'home_warden_config_path="{config}"\n{functions}\nweb_ui_fqdn\n'
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10, check=True)
    return result.stdout
