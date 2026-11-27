"""The default nginx.conf path follows the config repository's directory (nginx/conf) and still reads the former one
(nginx/server)."""

import subprocess
from pathlib import Path

import pytest

from app.cutover_preflight_cli import default_nginx_conf

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [
    "scripts/setup-service",
    "scripts/bootstrap",
    "scripts/on-deploy",
    "scripts/nginx-test-and-reload",
    "scripts/cutover-assess",
]


def _conf(home: Path, directory: str) -> Path:
    path = home / "home" / "nginx" / directory / "nginx.conf"
    path.parent.mkdir(parents=True)
    path.write_text("events {}\n")
    return path


def test_the_new_directory_wins_when_both_exist(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HOME_NGINX_CONF", raising=False)
    new = _conf(tmp_path, "conf")
    _conf(tmp_path, "server")
    assert default_nginx_conf() == new


def test_the_former_directory_is_used_when_only_it_exists(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HOME_NGINX_CONF", raising=False)
    former = _conf(tmp_path, "server")
    assert default_nginx_conf() == former


def test_the_environment_override_wins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HOME_NGINX_CONF", "/elsewhere/nginx.conf")
    _conf(tmp_path, "conf")
    assert default_nginx_conf() == Path("/elsewhere/nginx.conf")


def test_cutover_assess_prefers_the_new_directory_and_falls_back(tmp_path) -> None:
    source = (ROOT / "scripts/cutover-assess").read_text()
    function = source[source.index("conf_path() {") : source.index("preflight() {")]

    def resolved(home: Path) -> str:
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
        result = subprocess.run(["bash", "-c", function + "\nconf_path"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    only_old = tmp_path / "old"
    old = _conf(only_old, "server")
    assert resolved(only_old) == str(old)
    both = tmp_path / "both"
    new = _conf(both, "conf")
    _conf(both, "server")
    assert resolved(both) == str(new)


@pytest.mark.parametrize("name", SCRIPTS)
def test_each_script_prefers_the_new_directory_in_its_source(name) -> None:
    text = (ROOT / name).read_text()
    assert text.index("home/nginx/conf/nginx.conf") < text.index("home/nginx/server/nginx.conf")


def test_the_documentation_names_the_new_directory_only() -> None:
    for name in ["README.md", "docs/architecture-socket-activation.md"]:
        assert "nginx/server" not in (ROOT / name).read_text(), name


def _setup_service_function(name: str) -> str:
    source = (ROOT / "scripts/setup-service").read_text()
    start = source.index(f"{name}() {{")
    return source[start : source.index("\n}\n", start) + 3]


def test_the_conf_path_is_read_from_the_nginx_command_line() -> None:
    function = _setup_service_function("nginx_conf_from_args")
    line = "nginx: master process /usr/sbin/nginx -p /s/ -c /home/u/home/nginx/conf/nginx.conf -g daemon off;"
    out = subprocess.run(
        ["bash", "-c", function + f'\necho "{line}" | nginx_conf_from_args'], capture_output=True, text=True
    )
    assert out.stdout.strip() == "/home/u/home/nginx/conf/nginx.conf"


def _conf_changed(running: str, selected: str) -> bool:
    function = _setup_service_function("nginx_conf_changed")
    script = (
        f'nginx_master_conf() {{ echo "{running}"; }}\nhome_nginx_conf="{selected}"\n{function}\nnginx_conf_changed'
    )
    return subprocess.run(["bash", "-c", script]).returncode == 0


def test_a_different_running_conf_path_counts_as_changed() -> None:
    assert _conf_changed("/h/home/nginx/server/nginx.conf", "/h/home/nginx/conf/nginx.conf")


def test_the_same_or_an_unknown_running_conf_path_does_not() -> None:
    assert not _conf_changed("/h/home/nginx/conf/nginx.conf", "/h/home/nginx/conf/nginx.conf")
    assert not _conf_changed("", "/h/home/nginx/conf/nginx.conf")


def test_the_conf_path_check_runs_before_the_account_check_in_the_restart_block() -> None:
    text = (ROOT / "scripts/setup-service").read_text()
    block = text[text.index("if systemctl is-active --quiet home-warden.service") :]
    assert block.index("elif nginx_conf_changed; then") < block.index('elif [[ "$(nginx_master_ids)"')


def test_the_running_command_line_is_read_without_truncation() -> None:
    function = _setup_service_function("nginx_master_conf")
    assert "ps -ww -o args=" in function
