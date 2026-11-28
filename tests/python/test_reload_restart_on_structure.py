"""What a reload cannot apply is handled by the reload scripts: nginx and the recursor.

scripts/lib/config-fingerprint runs for real here. scripts/nginx-test-and-reload runs end to end with systemctl, nginx
and ps stubbed on PATH; the recursor step runs through its function with systemctl, pdns_recursor and rec_control
stubbed."""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "scripts" / "lib" / "config-fingerprint"


def bash(script: str, stdin: str = "", env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail\nsource "{LIB}"\n{script}'],
        input=stdin,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )


def listens(config: str) -> str:
    result = bash("hw_fingerprint_listens", stdin=config)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


# ---- fingerprints -------------------------------------------------------------------------------------------------


def test_listen_fingerprint_ignores_comments_order_and_spacing() -> None:
    one = listens("server {\n    listen 80;\n    listen [::]:80;\n    # listen 8445 ssl;\n}\n")
    assert one == listens("server {\n  listen   [::]:80;\n\n  listen 80;\n}\n")


def test_listen_fingerprint_changes_when_a_listener_is_added() -> None:
    assert listens("listen 80;\n") != listens("listen 80;\nlisten 443 ssl;\n")


def test_a_config_without_any_listen_line_hashes_the_empty_set_instead_of_failing() -> None:
    assert listens("events {}\nhttp {}\n") == listens("")


def test_listens_that_live_in_an_included_file_count_because_nginx_dash_T_prints_them() -> None:
    dump = "# configuration file /etc/x/nginx.conf:\nhttp {\n  include conf.d/*.conf;\n}\n"
    dump_with_included = dump + "# configuration file /etc/x/conf.d/a.conf:\nserver {\n    listen 443 ssl;\n}\n"
    assert listens(dump) != listens(dump_with_included)


def test_changed_means_a_saved_fingerprint_that_differs(tmp_path) -> None:
    state = tmp_path / "state"
    assert bash(f'hw_fingerprint_changed "{state}" abc').returncode == 1  # first run: nothing saved
    bash(f'hw_fingerprint_save "{state}" abc')
    assert bash(f'hw_fingerprint_changed "{state}" abc').returncode == 1
    assert bash(f'hw_fingerprint_changed "{state}" def').returncode == 0


def test_file_fingerprint_follows_symlinks_and_skips_missing_files(tmp_path) -> None:
    real = tmp_path / "real.yml"
    real.write_text("recursor:\n  threads: 2\n")
    link = tmp_path / "recursor.yml"
    link.symlink_to(real)
    first = bash(f'hw_fingerprint_files "{link}" "{tmp_path}/missing.yml"').stdout
    real.write_text("recursor:\n  threads: 4\n")
    assert bash(f'hw_fingerprint_files "{link}" "{tmp_path}/missing.yml"').stdout != first


# ---- nginx-test-and-reload, end to end ----------------------------------------------------------------------------


def run_nginx(
    tmp_path, conf: str, running_conf: str | None, state: str | None, unit_conf: str | None = None, dump_ok: bool = True
):
    """Returns (systemctl calls, output, saved listen fingerprint or '')."""
    bin_dir = tmp_path / "bin"
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf)
    calls = tmp_path / "calls"
    calls.write_text("")
    if state is not None:
        (scratch / "nginx-listens.sha256").write_text(state + "\n")
    running = running_conf if running_conf is not None else str(conf_path)
    unit = unit_conf if unit_conf is not None else str(conf_path)
    dump = f'echo "# configuration file {conf_path}:"; cat "{conf_path}"' if dump_ok else "true"
    stub(bin_dir, "nginx", f'case "$*" in *-T*) {dump};; esac\nexit 0\n')
    stub(bin_dir, "ps", f'echo "nginx: master process /usr/sbin/nginx -c {running} -g daemon off;"\n')
    stub(
        bin_dir,
        "systemctl",
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        "  *MainPID*) echo 4242;;\n"
        "  *ExecStart*) echo '{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -p /s/ -c "
        f"{unit} -g daemon off; ignore_errors=no }}';;\n"
        "esac\nexit 0\n",
    )
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME_WARDEN_SKIP_HOST_GUARD": "1",
        "SCRATCH_DIR": str(scratch),
        "HOME_NGINX_CONF": str(conf_path),
        "OWNER": "",
    }
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "nginx-test-and-reload")], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    saved = scratch / "nginx-listens.sha256"
    return calls.read_text(), result.stdout, saved.read_text().strip() if saved.exists() else ""


CONF = "server {\n    listen 443 ssl;\n}\n"


def test_nginx_is_reloaded_when_nothing_structural_changed(tmp_path) -> None:
    calls, _, _ = run_nginx(tmp_path, CONF, None, listens(CONF))
    assert "reload home-warden.service" in calls
    assert "restart" not in calls


def test_a_changed_listen_set_warns_and_reloads_but_does_not_restart_the_service_alone(tmp_path) -> None:
    calls, out, saved = run_nginx(tmp_path, CONF + "server {\n    listen [::]:443 ssl;\n}\n", None, listens(CONF))
    assert "WARN: the privileged listen directives" in out and "scripts/setup-service" in out
    assert "reload home-warden.service" in calls
    assert "restart" not in calls
    assert saved == listens(CONF), "the old fingerprint stays, so the warning repeats until setup-service ran"


def test_a_config_with_no_listen_line_still_reloads(tmp_path) -> None:
    calls, _, _ = run_nginx(tmp_path, "events {}\nhttp {}\n", None, listens(""))
    assert "reload home-warden.service" in calls


def test_nginx_is_restarted_when_it_runs_another_config_path_and_the_unit_points_at_the_new_one(tmp_path) -> None:
    calls, out, saved = run_nginx(tmp_path, CONF, "/old/place/nginx.conf", listens(CONF))
    assert "restart home-warden.service" in calls and "reload home-warden.service" not in calls
    assert saved == listens(CONF)


def test_a_unit_that_still_uses_the_old_path_gets_a_warning_and_a_reload_not_a_restart_loop(tmp_path) -> None:
    calls, out, _ = run_nginx(tmp_path, CONF, "/old/nginx.conf", listens(CONF), unit_conf="/old/nginx.conf")
    assert "WARN: home-warden.service starts nginx with -c /old/nginx.conf" in out
    assert "reload home-warden.service" in calls and "restart" not in calls


def test_the_first_run_only_records_the_listens_and_reloads(tmp_path) -> None:
    calls, _, saved = run_nginx(tmp_path, CONF, None, None)
    assert "reload home-warden.service" in calls and "restart" not in calls
    assert saved == listens(CONF)


# ---- recursor config, through its function -----------------------------------------------------------------------


def run_recursor(tmp_path, yaml_text: str, state: str | None, check_ok: bool = True, restart_ok: bool = True):
    bin_dir = tmp_path / "rbin"
    calls = tmp_path / "rcalls"
    calls.write_text("")
    yaml = tmp_path / "recursor.yml"
    yaml.write_text(yaml_text)
    state_file = tmp_path / "state"
    if state is not None:
        state_file.write_text(state + "\n")
    stub(bin_dir, "pdns_recursor", f'echo "pdns_recursor $*" >> "{calls}"\nexit {0 if check_ok else 1}\n')
    stub(bin_dir, "systemctl", f'echo "systemctl $*" >> "{calls}"\nexit {0 if restart_ok else 1}\n')
    stub(bin_dir, "rec_control", f'echo "rec_control $*" >> "{calls}"\nexit 0\n')
    script = f'log() {{ echo "$*"; }}\nhw_recursor_restart_if_changed "{yaml}" "{state_file}" pdns-recursor.service'
    result = bash(script, env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "HW_RECURSOR_PING_WAIT": "0"})
    fp = bash(f'hw_fingerprint_files "{yaml}"').stdout.strip()
    return result, calls.read_text(), state_file.read_text().strip() if state_file.exists() else "", fp


def test_the_recursor_first_run_records_and_restarts_nothing(tmp_path) -> None:
    result, calls, saved, fp = run_recursor(tmp_path, "recursor:\n  threads: 2\n", None)
    assert result.returncode == 0 and "systemctl" not in calls
    assert saved == fp


def test_an_unchanged_recursor_config_restarts_nothing(tmp_path) -> None:
    (tmp_path / "recursor.yml").write_text("recursor:\n  threads: 2\n")
    fp = bash(f'hw_fingerprint_files "{tmp_path}/recursor.yml"').stdout.strip()
    result, calls, _, _ = run_recursor(tmp_path, "recursor:\n  threads: 2\n", fp)
    assert result.returncode == 0 and calls == ""


def test_a_changed_valid_recursor_config_is_checked_then_restarted_then_pinged(tmp_path) -> None:
    result, calls, saved, fp = run_recursor(tmp_path, "recursor:\n  threads: 4\n", "oldfingerprint")
    assert result.returncode == 0
    lines = calls.splitlines()
    assert lines[0].startswith("pdns_recursor --config=check")
    assert lines[1] == "systemctl restart pdns-recursor.service"
    assert lines[2] == "rec_control ping"
    assert saved == fp


def test_an_invalid_recursor_config_is_never_restarted_into_and_the_fingerprint_stays(tmp_path) -> None:
    result, calls, saved, _ = run_recursor(tmp_path, "recursor:\n  nonsense: 1\n", "oldfingerprint", check_ok=False)
    assert result.returncode == 1 and "FAIL" in result.stdout
    assert "systemctl" not in calls
    assert saved == "oldfingerprint"


def test_a_failed_recursor_restart_fails_the_run_and_keeps_the_old_fingerprint(tmp_path) -> None:
    result, _, saved, _ = run_recursor(tmp_path, "recursor:\n  threads: 4\n", "oldfingerprint", restart_ok=False)
    assert result.returncode == 1
    assert saved == "oldfingerprint"


def test_the_pdns_script_applies_the_recursor_config_before_reload_zones() -> None:
    text = (ROOT / "scripts" / "pdns-test-and-reload").read_text()
    assert text.index("hw_recursor_restart_if_changed") < text.index("rec_control reload-zones >/dev/null")


def test_a_recursor_that_never_answers_its_control_socket_after_the_restart_fails_the_run(tmp_path) -> None:
    bin_dir = tmp_path / "rbin"
    stub(bin_dir, "pdns_recursor", "exit 0\n")
    stub(bin_dir, "systemctl", "exit 0\n")
    stub(bin_dir, "rec_control", "exit 1\n")
    yaml = tmp_path / "recursor.yml"
    yaml.write_text("recursor:\n  threads: 4\n")
    state = tmp_path / "state"
    state.write_text("oldfingerprint\n")
    script = f'log() {{ echo "$*"; }}\nhw_recursor_restart_if_changed "{yaml}" "{state}" pdns-recursor.service'
    result = bash(script, env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "HW_RECURSOR_PING_WAIT": "0"})
    assert result.returncode == 1
    assert "recursor restart OK" not in result.stdout and "did not answer its control socket" in result.stdout


def dump_of(config_text: str) -> str:
    """What `nginx -T` prints for a config: a header line per file, then the file."""
    return "# configuration file /etc/x/nginx.conf:\n" + config_text


def test_recording_the_listens_after_setup_service_clears_the_listen_warning(tmp_path) -> None:
    changed = CONF + "server {\n    listen [::]:443 ssl;\n}\n"
    calls, out, _ = run_nginx(tmp_path, changed, None, listens(CONF))
    assert "WARN: the privileged listen directives" in out
    # what setup-service does after it restarted the socket and the service: pipe `sudo nginx -T` in
    scratch = tmp_path / "scratch"
    recorded = bash(f'hw_nginx_record_listens "{scratch}"', stdin=dump_of(changed))
    assert recorded.returncode == 0, recorded.stderr
    state = (scratch / "nginx-listens.sha256").read_text().strip()
    assert state == listens(dump_of(changed))
    calls, out, saved = run_nginx(tmp_path, changed, None, state)
    assert "WARN" not in out and "reload home-warden.service" in calls
    assert saved == state


def test_a_failed_nginx_dump_is_never_recorded_as_an_empty_listen_set(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    for failed in ["", "nginx: [emerg] cannot load certificate\n"]:
        result = bash(f'hw_nginx_record_listens "{scratch}"', stdin=failed)
        assert result.returncode == 1
        assert not (scratch / "nginx-listens.sha256").exists()


def test_a_path_change_that_comes_with_a_new_privileged_listen_is_only_reloaded_and_left_to_setup_service(
    tmp_path,
) -> None:
    changed = CONF + "server {\n    listen [::]:443 ssl;\n}\n"
    calls, out, saved = run_nginx(tmp_path, changed, "/old/place/nginx.conf", listens(CONF))
    assert "restart" not in calls and "reload home-warden.service" in calls
    assert "WARN: the privileged listen directives" in out
    assert saved == listens(CONF)


def test_saving_creates_a_missing_directory_and_an_unwritable_state_file_is_a_failure_not_a_crash(tmp_path) -> None:
    state = tmp_path / "new" / "dir" / "state"
    assert bash(f'hw_fingerprint_save "{state}" abc').returncode == 0
    assert state.read_text().strip() == "abc"
    state.chmod(0o444)
    result = bash(f'hw_fingerprint_save "{state}" def || echo FAILED')
    assert "FAILED" in result.stdout


def test_setup_service_records_the_listens_once_the_service_runs_and_the_unit_carries_scratch_dir() -> None:
    text = (ROOT / "scripts" / "setup-service").read_text()
    assert text.index("    confirm_running\n") < text.index("hw_nginx_record_listens")
    assert "if ! sudo nginx -p" in text and "-T -c" in text, (
        "needs sudo for the served config, and must not abort setup"
    )
    unit = (ROOT / "etc" / "systemd" / "home-warden-pdns-reload.service").read_text()
    assert "Environment=SCRATCH_DIR=@@SCRATCH_DIR@@" in unit


def test_no_machine_hostname_is_named_in_the_new_text() -> None:
    for name in ["scripts/pdns-test-and-reload", "scripts/lib/config-fingerprint", "docs/dns-tinydns-migration.md"]:
        assert "tron" not in (ROOT / name).read_text().lower().replace("tronc", ""), name


def test_the_listen_fingerprint_is_a_set_of_privileged_addresses_only() -> None:
    base = "server {\n    listen 443 ssl;\n}\n"
    # every vhost repeats its own listen line, and ssl/default_server are flags, not part of the address
    assert listens(base) == listens(
        base + "server {\n    listen 443 ssl;\n}\nserver {\n    listen 443 ssl default_server;\n}\n"
    )
    # nginx opens unprivileged ports itself on a reload, and unix sockets are not ports
    assert listens(base) == listens(base + "server {\n    listen 8443 ssl;\n    listen unix:/run/x.sock;\n}\n")
    # a privileged address that is new is a change
    assert listens(base) != listens(base + "server {\n    listen [::]:443 ssl;\n}\n")
    assert listens(base) != listens(base + "server {\n    listen 127.0.0.1:80;\n}\n")


def test_a_new_unprivileged_listen_is_just_reloaded_without_a_warning(tmp_path) -> None:
    calls, out, saved = run_nginx(tmp_path, CONF + "server {\n    listen 8443 ssl;\n}\n", None, listens(CONF))
    assert "WARN" not in out
    assert "reload home-warden.service" in calls and "restart" not in calls
    assert saved == listens(CONF)


def test_a_failed_nginx_dump_neither_warns_about_a_change_nor_records_a_hash(tmp_path) -> None:
    calls, out, saved = run_nginx(tmp_path, CONF, None, listens(CONF), dump_ok=False)
    assert "nginx -T printed no configuration" in out
    assert "privileged listen directives" not in out
    assert "reload home-warden.service" in calls
    (tmp_path / "again").mkdir()
    _, _, first_saved = run_nginx(tmp_path / "again", CONF, None, None, dump_ok=False)
    assert first_saved == "", "a failed dump on the first run must not record the empty set"


def test_a_failing_systemctl_show_does_not_abort_the_reload(tmp_path) -> None:
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "systemctl", "exit 1\n")
    result = bash(
        "hw_unit_nginx_conf home-warden.service\necho survived", env={"PATH": f"{bin_dir}:{os.environ['PATH']}"}
    )
    assert result.returncode == 0 and result.stdout.strip() == "survived"


# ---- review round: parsing, coverage, save ordering, manifest --------------------------------------------------------


def test_a_listen_inside_a_one_line_server_block_counts() -> None:
    assert listens("server { listen 80; }\n") != listens("server { listen 80; }\nserver { listen [::]:443 ssl; }\n")
    assert listens("server {\n  listen\n    [::]:443\n    ssl;\n}\n") == listens("server { listen [::]:443 ssl; }\n")


def test_a_listen_with_an_address_and_no_port_is_port_80() -> None:
    assert listens("listen [::];\n") == listens("listen [::]:80;\n")
    assert listens("listen [::];\n") != listens("")
    # a bare high port stays out, like any unprivileged port
    assert listens("listen 8080;\n") == listens("")


def test_a_privileged_listen_the_sockets_cannot_supply_is_not_recorded(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "nginx-listens.sha256").write_text("old\n")
    result = bash(f'hw_nginx_record_listens "{scratch}"', stdin=dump_of("server { listen 127.0.0.1:443 ssl; }\n"))
    assert result.returncode == 2
    assert "127.0.0.1:443" in result.stderr
    assert (scratch / "nginx-listens.sha256").read_text() == "old\n"


def test_the_listens_setup_can_supply_are_recorded(tmp_path) -> None:
    scratch = tmp_path / "scratch"
    conf = "server { listen 80; listen [::]:80; listen 443 ssl; listen [::]:443 ssl; listen 8443 ssl; }\n"
    assert bash(f'hw_nginx_record_listens "{scratch}"', stdin=dump_of(conf)).returncode == 0


def test_the_files_manifest_cannot_be_forged_by_a_file_whose_content_looks_like_another_record(tmp_path) -> None:
    (tmp_path / "a.yml").write_text('"x"')
    (tmp_path / "b.yml").write_text('"y"')
    both = bash(f'hw_fingerprint_files "{tmp_path}/a.yml" "{tmp_path}/b.yml"').stdout
    (tmp_path / "forged").mkdir()
    (tmp_path / "forged" / "a.yml").write_text('"x"' + "\n" + "b.yml" + "\n" + '"y"')
    forged = bash(f'hw_fingerprint_files "{tmp_path}/forged/a.yml"').stdout
    assert both != forged


def test_the_recursor_fingerprint_is_saved_only_after_it_answers_so_a_dead_restart_is_retried(tmp_path) -> None:
    bin_dir = tmp_path / "rbin"
    stub(bin_dir, "pdns_recursor", "exit 0\n")
    stub(bin_dir, "systemctl", "exit 0\n")
    stub(bin_dir, "rec_control", "exit 1\n")
    yaml = tmp_path / "recursor.yml"
    yaml.write_text("recursor:\n  threads: 4\n")
    state = tmp_path / "state"
    state.write_text("oldfingerprint\n")
    script = f'log() {{ echo "$*"; }}\nhw_recursor_restart_if_changed "{yaml}" "{state}" pdns-recursor.service'
    result = bash(script, env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "HW_RECURSOR_PING_WAIT": "0"})
    assert result.returncode == 1
    assert state.read_text().strip() == "oldfingerprint"


def test_an_unwritable_state_file_fails_the_first_run_and_the_restart_instead_of_logging_success(tmp_path) -> None:
    bin_dir = tmp_path / "rbin"
    stub(bin_dir, "pdns_recursor", "exit 0\n")
    stub(bin_dir, "systemctl", "exit 0\n")
    stub(bin_dir, "rec_control", "exit 0\n")
    yaml = tmp_path / "recursor.yml"
    yaml.write_text("recursor:\n  threads: 4\n")
    blocked = tmp_path / "blocked"
    blocked.write_text("a file, so the state path below it cannot be created")
    state = blocked / "state"
    script = (
        f'log() {{ echo "$*"; }}\nif ! hw_recursor_restart_if_changed "{yaml}" "{state}" pdns-recursor.service;'
        " then echo failed; fi"
    )
    result = bash(script, env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "HW_RECURSOR_PING_WAIT": "0"})
    assert "failed" in result.stdout
    assert "recorded the recursor config fingerprint" not in result.stdout


def test_an_unreadable_unit_execstart_never_restarts_for_a_changed_config_path(tmp_path) -> None:
    bin_dir = tmp_path / "bin"
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(CONF)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    calls = tmp_path / "calls"
    calls.write_text("")
    stub(
        bin_dir,
        "nginx",
        f'case "$*" in *-T*) echo "# configuration file {conf_path}:"; cat "{conf_path}";; esac\nexit 0\n',
    )
    stub(bin_dir, "ps", 'echo "nginx: master process /usr/sbin/nginx -c /old/nginx.conf -g daemon off;"\n')
    # ExecStart cannot be read: the show prints nothing
    stub(bin_dir, "systemctl", f'echo "$*" >> "{calls}"\ncase "$*" in *MainPID*) echo 4242;; esac\nexit 0\n')
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME_WARDEN_SKIP_HOST_GUARD": "1",
        "SCRATCH_DIR": str(scratch),
        "HOME_NGINX_CONF": str(conf_path),
        "OWNER": "",
    }
    (scratch / "nginx-listens.sha256").write_text(listens(CONF) + "\n")
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "nginx-test-and-reload")], capture_output=True, text=True, env=env
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "reload home-warden.service" in calls.read_text() and "restart" not in calls.read_text()


def test_quoted_listen_tokens_are_read_like_nginx_reads_them() -> None:
    assert listens('server { listen "443" ssl; }\n') == listens("server { listen 443 ssl; }\n")
    assert listens("server { 'listen' '[::]:80'; }\n") == listens("server { listen [::]:80; }\n")


def test_a_datagram_listener_is_a_different_address_and_is_never_supported(tmp_path) -> None:
    tcp = "server { listen 443 ssl; }\n"
    assert listens(tcp) != listens(tcp + "server { listen 443 quic reuseport; }\n")
    assert listens(tcp) != listens(tcp + "server { listen 443 udp; }\n")
    scratch = tmp_path / "scratch"
    result = bash(f'hw_nginx_record_listens "{scratch}"', stdin=dump_of(tcp + "server { listen 443 quic; }\n"))
    assert result.returncode == 2 and "443/udp" in result.stderr
