"""scripts/healthcheck: an idle socket-activated service is healthy when its probe answers.

The mail says why it failed, since when and for how long. Runs the real script with stub systemctl, curl and sendmail
on PATH (no network, no real units) and a fixed TZ.
"""

import os
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HEALTHCHECK = REPO / "scripts" / "healthcheck"


def _stubs(tmp_path: Path, service: str, socket: str, http: str = "200") -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "systemctl").write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "$1" == is-active ]]; then\n'
        '  case "${@: -1}" in\n'
        f"    home-warden.service) echo {service}; [[ {service} == active ]] ;;\n"
        f"    home-warden.socket) echo {socket}; [[ {socket} == active ]] ;;\n"
        "  esac\n"
        "  exit\nfi\nexit 0\n"
    )
    (bin_dir / "curl").write_text(f'#!/usr/bin/env bash\nprintf "{http}"\n')
    mail_out = tmp_path / "mail.out"
    (bin_dir / "sendmail").write_text(f'#!/usr/bin/env bash\ncat >> "{mail_out}"\nprintf "=====\\n" >> "{mail_out}"\n')
    for stub in bin_dir.iterdir():
        stub.chmod(0o755)
    # Under systemd (CI included) INVOCATION_ID makes the script print instead of appending to its log file.
    base = {key: value for key, value in os.environ.items() if key != "INVOCATION_ID"}
    return {
        **base,
        "HEALTHCHECK_EMAIL_TO": "ops@example.test",
        "HOME_WARDEN_SKIP_HOST_GUARD": "1",
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "SCRATCH_DIR": str(tmp_path / "scratch"),
        "TZ": "America/New_York",
    }


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(HEALTHCHECK), *args], capture_output=True, env=env, text=True, timeout=30)


def _mail(tmp_path: Path) -> str:
    path = tmp_path / "mail.out"
    return path.read_text() if path.exists() else ""


def test_idle_service_with_a_listening_socket_is_healthy_and_sends_no_mail(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="active")
    result = _run(env, "--check-only")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _run(env).returncode == 0
    assert _mail(tmp_path) == ""
    log = (tmp_path / "scratch" / "healthcheck.log").read_text()
    assert "OK " in log
    assert "this probe started it" in log


def test_a_stopped_socket_is_unhealthy_and_the_mail_says_nothing_listens(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    assert _run(env, "--check-only").returncode == 1
    _run(env)
    mail = _mail(tmp_path)
    assert "UNHEALTHY" in mail
    assert "nothing is listening on ports 80 and 443" in mail
    assert "systemctl status home-warden.service home-warden.socket" in mail


def test_a_failed_service_is_unhealthy_with_the_journal_command(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="failed", socket="active")
    _run(env)
    mail = _mail(tmp_path)
    assert "has failed" in mail
    assert "journalctl -u home-warden.service" in mail


def test_the_mail_carries_local_time_and_utc_and_the_log_both_zones(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    _run(env)
    mail = _mail(tmp_path)
    assert " EST" in mail or " EDT" in mail
    assert "UTC" in mail
    log = (tmp_path / "scratch" / "healthcheck.log").read_text()
    assert "Z (" in log


def test_recovery_mail_says_when_it_started_and_how_long_and_what_was_wrong(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    _run(env)
    state = tmp_path / "scratch" / "healthcheck.state"
    lines = state.read_text().splitlines()
    assert any(line.startswith("first_fail_epoch=") and line != "first_fail_epoch=0" for line in lines)
    five_minutes_ago = int(time.time()) - 300
    first_line = _first(lines, "first_fail_epoch=")
    state.write_text(state.read_text().replace(first_line, f"first_fail_epoch={five_minutes_ago}"))
    env = _stubs(tmp_path, service="active", socket="active")
    _run(env)
    recovery = _mail(tmp_path).split("=====")[-2]
    assert "RECOVERED" in recovery
    assert "Unhealthy from" in recovery
    assert "about 5 min" in recovery
    assert "What was wrong: home-warden.service is inactive and home-warden.socket is inactive" in recovery


def test_a_restart_loop_is_not_mistaken_for_an_idle_start(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="activating", socket="active")
    assert _run(env, "--check-only").returncode == 1
    _run(env)
    mail = _mail(tmp_path)
    assert "UNHEALTHY" in mail
    assert "is not active (activating)" in mail
    assert "this probe started it" not in (tmp_path / "scratch" / "healthcheck.log").read_text()


def test_an_hour_and_a_half_outage_is_written_in_hours_and_minutes(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    _run(env)
    state = tmp_path / "scratch" / "healthcheck.state"
    lines = state.read_text().splitlines()
    long_ago = int(time.time()) - 5700
    state.write_text(state.read_text().replace(_first(lines, "first_fail_epoch="), f"first_fail_epoch={long_ago}"))
    _run(_stubs(tmp_path, service="active", socket="active"))
    assert "about 1h 35min" in _mail(tmp_path)


def test_a_later_failure_keeps_the_first_failure_time_and_reason(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    _run(env)
    state = tmp_path / "scratch" / "healthcheck.state"
    first_line = _first(state.read_text().splitlines(), "first_fail_epoch=")
    earlier = f"first_fail_epoch={int(time.time()) - 300}"
    state.write_text(state.read_text().replace(first_line, earlier))
    _run(_stubs(tmp_path, service="failed", socket="active"))
    lines = state.read_text().splitlines()
    assert earlier in lines
    assert any(line.startswith("fail_detail=") and "nothing is listening" in line for line in lines)


def _first(lines: list[str], prefix: str) -> str:
    return next(line for line in lines if line.startswith(prefix))


def test_a_failed_mail_keeps_the_outage_start_and_is_retried(tmp_path: Path) -> None:
    env = _stubs(tmp_path, service="inactive", socket="inactive")
    sendmail = tmp_path / "bin" / "sendmail"
    sendmail.write_text("#!/usr/bin/env bash\ncat >/dev/null\nexit 75\n")
    _run(env)
    state = tmp_path / "scratch" / "healthcheck.state"
    lines = state.read_text().splitlines()
    first_line = _first(lines, "first_fail_epoch=")
    assert first_line != "first_fail_epoch=0"
    assert "status=fail" in lines
    assert "last_alert_epoch=0" in lines
    earlier = f"first_fail_epoch={int(time.time()) - 300}"
    state.write_text(state.read_text().replace(first_line, earlier))
    _stubs(tmp_path, service="inactive", socket="inactive")
    _run(env)
    mail = _mail(tmp_path)
    assert "UNHEALTHY" in mail
    assert "for 5 min" in mail
    assert earlier in state.read_text().splitlines()
