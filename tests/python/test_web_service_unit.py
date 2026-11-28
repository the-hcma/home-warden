"""The web UI backend's systemd unit and the setup-service wiring that enables it only when `fqdn` is set (#280)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from app.home_warden_config import BACKEND_LOOPBACK_HOST, BACKEND_LOOPBACK_PORT, load_config

REPO = Path(__file__).resolve().parents[2]
SETUP = REPO / "scripts" / "setup-service"
UNIT = REPO / "etc" / "systemd" / "home-warden-web.service"

# Settings the script and the Python loader must read alike: valid, padded, other quoting, nested, wrong type, broken.
CONFIGS = [
    'fqdn = "warden.example.com"\n',
    '# web UI\nfqdn = "warden.example.com"  # the name\n',
    'fqdn="warden.example.com"',
    "fqdn = 'warden.example.com'\n",
    'fqdn = "  warden.example.com  "\n',
    'fqdn = ""\n',
    'fqdn = "   "\n',
    "fqdn = 7\n",
    'fqdn = ["warden.example.com"]\n',
    '[web]\nfqdn = "warden.example.com"\n',
    'other = "x"\n',
    'fqdn = "unterminated\n',
    "",
]


def _bash_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SETUP.read_text(), re.S | re.M)
    assert match, f"{name} not found in setup-service"
    return match.group(0)


def _script_fqdn(config: Path) -> str:
    script = f'home_warden_config_path="{config}"\n{_bash_function("web_ui_fqdn")}\nweb_ui_fqdn\n'
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20, check=True)
    return result.stdout


@pytest.mark.parametrize("text", CONFIGS)
def test_setup_service_reads_the_fqdn_exactly_as_the_backend_does(text: str, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(text)
    assert _script_fqdn(config) == load_config(config).fqdn


def test_setup_service_reads_no_fqdn_from_a_missing_file(tmp_path: Path) -> None:
    assert _script_fqdn(tmp_path / "missing.toml") == ""


def test_setup_service_installs_and_starts_the_unit_only_when_the_web_ui_is_enabled() -> None:
    text = SETUP.read_text()
    assert "web_ui_enabled=0" in text
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n\s+expand_unit .*home-warden-web\.service", text)
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n\s+# .*\n\s+run sudo systemctl enable home-warden-web", text)
    assert "run sudo systemctl restart home-warden-web.service" in text
    assert "run sudo systemctl disable --now home-warden-web.service" in text


def test_the_unit_does_not_set_no_new_privileges_because_the_pam_login_needs_the_setgid_helper() -> None:
    directives = [line for line in UNIT.read_text().splitlines() if not line.lstrip().startswith("#")]
    assert not any(line.startswith("NoNewPrivileges") for line in directives)


def test_the_unit_reads_the_same_config_directory_as_setup_service() -> None:
    assert "Environment=XDG_CONFIG_HOME=@@XDG_CONFIG_HOME@@" in UNIT.read_text()
    assert "@@XDG_CONFIG_HOME@@|${XDG_CONFIG_HOME:-${HOME}/.config}" in SETUP.read_text()


def test_the_unit_runs_the_loopback_backend_as_the_owner() -> None:
    text = UNIT.read_text()
    assert "User=@@OWNER@@" in text
    assert "ExecStart=@@REPO_DIR@@/scripts/catalog-health-server" in text
    assert f"HOME_WARDEN_LISTEN_HOST={BACKEND_LOOPBACK_HOST}" in text
    assert f"HOME_WARDEN_LISTEN_PORT={BACKEND_LOOPBACK_PORT}" in text
    assert "Restart=on-failure" in text
    assert "WantedBy=multi-user.target" in text
