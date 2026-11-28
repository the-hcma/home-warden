"""The web UI backend's systemd unit and the setup-service wiring that enables it only when `fqdn` is set (#280)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.home_warden_config import BACKEND_LOOPBACK_HOST, BACKEND_LOOPBACK_PORT, load_config

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


REPO = Path(__file__).resolve().parents[2]


SETUP = REPO / "scripts" / "setup-service"


UNIT = REPO / "etc" / "systemd" / "home-warden-web.service"


def test_a_config_in_a_directory_that_cannot_be_searched_is_an_error_not_an_unset_fqdn(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    config = locked / "config.toml"
    config.write_text('fqdn = "warden.example.com"\n')
    locked.chmod(0)
    try:
        if os.access(locked, os.X_OK):
            pytest.skip("running as a user that can search a mode 0 directory")
        result = _run_fqdn(config, f"{_python3_dir(tmp_path)}{os.pathsep}/usr/bin:/bin")
    finally:
        locked.chmod(0o700)
    assert result.returncode != 0 and result.stdout == ""
    assert "cannot look at" in result.stderr


def test_a_config_that_exists_but_cannot_be_read_is_an_error_not_an_unset_fqdn(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('fqdn = "warden.example.com"\n')
    config.chmod(0)
    try:
        if os.access(config, os.R_OK):
            pytest.skip("running as a user that can read a mode 0 file")
        result = _run_fqdn(config, f"{_python3_dir(tmp_path)}{os.pathsep}/usr/bin:/bin")
    finally:
        config.chmod(0o600)
    assert result.returncode != 0
    assert "not a readable file" in result.stderr
    assert result.stdout == ""


def test_a_config_that_is_genuinely_absent_is_unset_not_an_error(tmp_path: Path) -> None:
    result = _run_fqdn(tmp_path / "nowhere" / "config.toml", f"{_python3_dir(tmp_path)}{os.pathsep}/usr/bin:/bin")
    assert result.returncode == 0 and result.stdout == ""


def test_a_directory_where_the_config_should_be_is_an_error(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.mkdir()
    result = _run_fqdn(config, f"{_python3_dir(tmp_path)}{os.pathsep}/usr/bin:/bin")
    assert result.returncode != 0 and result.stdout == ""


def test_a_missing_interpreter_is_an_error_not_an_unset_fqdn(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('fqdn = "warden.example.com"\n')
    only_stat = tmp_path / "nobin"
    only_stat.mkdir()
    stat = shutil.which("stat")
    assert stat
    (only_stat / "stat").symlink_to(stat)  # the script looks at the file first; python3 is the one thing missing
    result = _run_fqdn(config, str(only_stat))
    assert result.returncode != 0
    assert result.stdout == ""
    assert "python3 not found" in result.stderr and "3.11" not in result.stderr


def test_a_python_without_tomllib_names_that_cause(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('fqdn = "warden.example.com"\n')
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "tomllib.py").write_text('raise ImportError("no tomllib here")\n')
    script = f'home_warden_config_path="{config}"\n{_bash_function("web_ui_fqdn")}\nweb_ui_fqdn\n'
    bash = shutil.which("bash")
    assert bash
    env = {"PATH": f"{_python3_dir(tmp_path)}{os.pathsep}/usr/bin:/bin", "HOME": str(tmp_path), "PYTHONPATH": str(shim)}
    result = subprocess.run([bash, "-c", script], capture_output=True, text=True, timeout=20, env=env, check=False)
    assert result.returncode != 0 and result.stdout == ""
    assert "3.11 or newer (tomllib)" in result.stderr


def test_a_unit_that_is_disabled_but_still_running_is_stopped_when_the_web_ui_is_turned_off() -> None:
    text = SETUP.read_text()
    pattern = (
        r"elif systemctl is-enabled --quiet home-warden-web\.service 2>/dev/null \|\|\n"
        r"\s+systemctl is-active --quiet home-warden-web\.service"
    )
    assert re.search(pattern, text)


def test_every_path_valued_environment_assignment_in_the_unit_is_quoted() -> None:
    lines = [line for line in UNIT.read_text().splitlines() if line.startswith("Environment=")]
    path_valued = [line for line in lines if "@@" in line or line.startswith("Environment=PATH")]
    assert path_valued
    for line in path_valued:
        assert re.fullmatch(r'Environment="[A-Z_]+=[^"]*"', line), line


@pytest.mark.parametrize(
    "path",
    ["/home/me/.config", "/home/me/my files/conf", "/srv/home-warden/conf/pki", "/home/a.b_c/d@e:f+g,h=i~j-k"],
)
def test_ordinary_paths_are_accepted_for_the_unit(path: str) -> None:
    assert _problem(path)[0] == 1


@pytest.mark.parametrize(
    "path", ["/home/a&b", "/home/a|b", "/home/a\\b", "/home/a%b", '/home/a"b', "/home/a$b", "/home/a\nb", ""]
)
def test_paths_that_sed_and_systemd_would_read_differently_are_refused(path: str) -> None:
    code, message = _problem(path)
    assert code == 0 and message


def test_setup_service_checks_for_uv_before_installing_the_web_unit() -> None:
    text = SETUP.read_text()
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n(?:.*\n){1,40}?.*\.local/bin/uv", text)
    assert "ERROR: uv not found" in text


def test_setup_service_installs_and_starts_the_unit_only_when_the_web_ui_is_enabled() -> None:
    text = SETUP.read_text()
    assert "web_ui_enabled=0" in text
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n\s+expand_unit .*home-warden-web\.service", text)
    assert re.search(r"if \(\(web_ui_enabled\)\); then\n\s+# .*\n\s+run sudo systemctl enable home-warden-web", text)
    assert "run sudo systemctl restart home-warden-web.service" in text
    assert "run sudo systemctl disable --now home-warden-web.service" in text


def test_setup_service_reads_no_fqdn_from_a_missing_file(tmp_path: Path) -> None:
    assert _script_fqdn(tmp_path / "missing.toml") == ""


@pytest.mark.parametrize("text", CONFIGS)
def test_setup_service_reads_the_fqdn_exactly_as_the_backend_does(text: str, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(text)
    assert _script_fqdn(config) == load_config(config).fqdn


def test_setup_service_refuses_to_enable_the_unit_until_the_ui_bundle_is_built() -> None:
    text = SETUP.read_text()
    assert re.search(
        r'if \[\[ ! -s "\$\{repo_dir\}/app/api/static/dist/main\.js" \]\]; then\n(?:.*\n){1,4}?\s+missing=1\n',
        text,
    )
    assert "cd ${repo_dir}/web && pnpm install --frozen-lockfile && pnpm run build" in text


def test_setup_service_refuses_to_install_the_web_unit_with_an_unsafe_path_before_changing_anything() -> None:
    text = SETUP.read_text()
    block = text[text.index("local path_label path_value problem") :]
    block = block[: block.index("scripts/catalog-health-server")]
    for name in (
        "repo_dir",
        "HOME",
        "scratch_dir",
        "conf_dir",
        "home_warden_config_dir",
        "services_json",
        "pdns_zones_yaml",
        "client_pki_store",
    ):
        assert name in block
    assert "missing=1" in block


def test_setup_service_stops_instead_of_disabling_the_web_ui_when_it_cannot_read_the_config() -> None:
    text = SETUP.read_text()
    assert re.search(r"if ! web_ui_fqdn_value=\"\$\(web_ui_fqdn\)\"; then\n\s+echo .*\n\s+exit 1", text)


def test_the_unit_and_setup_service_pass_the_resolved_paths_to_the_backend() -> None:
    unit = UNIT.read_text()
    for line in (
        'Environment="SERVICES_JSON_PATH=@@WEB_SERVICES_JSON_PATH@@"',
        'Environment="PDNS_ZONES_YAML=@@WEB_PDNS_ZONES_YAML@@"',
        'Environment="HOME_WARDEN_PKI_STORE=@@CLIENT_PKI_STORE@@"',
    ):
        assert line in unit
    setup = SETUP.read_text()
    assert "@@WEB_SERVICES_JSON_PATH@@|${services_json:-${default_services_json}}|g" in setup
    assert "@@WEB_PDNS_ZONES_YAML@@|${pdns_zones_yaml:-${default_pdns_zones_yaml}}|g" in setup


def test_the_unit_does_not_set_no_new_privileges_because_the_pam_login_needs_the_setgid_helper() -> None:
    directives = [line for line in UNIT.read_text().splitlines() if not line.lstrip().startswith("#")]
    assert not any(line.startswith("NoNewPrivileges") for line in directives)


def test_the_unit_reads_the_same_config_directory_as_setup_service() -> None:
    assert 'Environment="XDG_CONFIG_HOME=@@XDG_CONFIG_HOME@@"' in UNIT.read_text()
    assert "@@XDG_CONFIG_HOME@@|${XDG_CONFIG_HOME:-${HOME}/.config}|g" in SETUP.read_text()


def test_the_unit_runs_the_loopback_backend_as_the_owner() -> None:
    text = UNIT.read_text()
    assert "User=@@OWNER@@" in text
    assert "ExecStart=@@REPO_DIR@@/scripts/catalog-health-server" in text
    assert f"HOME_WARDEN_LISTEN_HOST={BACKEND_LOOPBACK_HOST}" in text
    assert f"HOME_WARDEN_LISTEN_PORT={BACKEND_LOOPBACK_PORT}" in text
    assert "Restart=on-failure" in text
    assert "WantedBy=multi-user.target" in text


def _bash_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SETUP.read_text(), re.S | re.M)
    assert match, f"{name} not found in setup-service"
    return match.group(0)


def _problem(path: str) -> tuple[int, str]:
    script = f'{_setup_function("unit_path_problem")}\nunit_path_problem "$1"\n'
    bash = shutil.which("bash")
    assert bash
    result = subprocess.run([bash, "-c", script, "x", path], capture_output=True, text=True, timeout=20, check=False)
    return result.returncode, result.stdout.strip()


def _python3_dir(tmp_path: Path) -> Path:
    """A directory whose `python3` is the interpreter running the tests (the uv-managed one), not the one on PATH."""
    bin_dir = tmp_path / "pybin"
    bin_dir.mkdir(exist_ok=True)
    link = bin_dir / "python3"
    if not link.exists():
        link.symlink_to(sys.executable)
    return bin_dir


def _run_fqdn(config: Path, path: str) -> subprocess.CompletedProcess[str]:
    script = f'home_warden_config_path="{config}"\n{_bash_function("web_ui_fqdn")}\nweb_ui_fqdn\n'
    env = {"PATH": path, "HOME": str(config.parent)}
    bash = shutil.which("bash")  # resolved before PATH is narrowed to the test's own directories
    assert bash
    return subprocess.run([bash, "-c", script], capture_output=True, text=True, timeout=20, env=env, check=False)


def _script_fqdn(config: Path) -> str:
    result = _run_fqdn(config, f"{_python3_dir(config.parent)}{os.pathsep}/usr/bin:/bin")
    assert result.returncode == 0, result.stderr
    return result.stdout


def _setup_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SETUP.read_text(), re.S | re.M)
    assert match, f"{name} not found in setup-service"
    return match.group(0)
