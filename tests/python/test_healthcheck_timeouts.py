"""scripts/healthcheck's HTTPS probe sets both --connect-timeout and --max-time.

Runs the real script in --check-only mode (no mail, no state) with stub curl
and systemctl on PATH, and inspects the argv curl was called with.
"""

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HEALTHCHECK = REPO / "scripts" / "healthcheck"


def test_probe_sets_default_connect_and_total_timeouts(tmp_path: Path) -> None:
    argv = _curl_argv(tmp_path, {})
    assert _flag(argv, "--connect-timeout") == "3"
    assert _flag(argv, "--max-time") == "5"


def test_probe_timeouts_follow_their_env_overrides(tmp_path: Path) -> None:
    argv = _curl_argv(tmp_path, {"HEALTHCHECK_CONNECT_TIMEOUT_SEC": "2", "HEALTHCHECK_TIMEOUT_SEC": "9"})
    assert _flag(argv, "--connect-timeout") == "2"
    assert _flag(argv, "--max-time") == "9"


def _curl_argv(tmp_path: Path, overrides: dict[str, str]) -> list[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    record = tmp_path / "curl-argv"
    (stubs / "curl").write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" >"{record}"\nprintf 200\n')
    (stubs / "systemctl").write_text("#!/usr/bin/env bash\nexit 0\n")
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = {
        **os.environ,
        **overrides,
        "HOME_WARDEN_SKIP_HOST_GUARD": "1",
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "SCRATCH_DIR": str(tmp_path / "scratch"),
    }
    result = subprocess.run([str(HEALTHCHECK), "--check-only"], capture_output=True, env=env, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return record.read_text().splitlines()


def _flag(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]
