"""scripts/client-pki pins tiny-pki to home-warden's store and passes every argument through.

A stub `uv` on PATH records the argv the wrapper execs, covering store resolution
(`HOME_WARDEN_PKI_STORE`, else `conf/pki` in the repo) without touching the real
store. One test runs the real wrapper end to end against a throwaway store.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLIENT_PKI = REPO / "scripts" / "client-pki"


def test_arguments_pass_through_unchanged(tmp_path: Path) -> None:
    argv = _stub_uv_argv(tmp_path, {"HOME_WARDEN_PKI_STORE": str(tmp_path / "pki")}, "create", "client", "alice phone")
    assert argv[argv.index("--store") + 2 :] == ["create", "client", "alice phone"]


def test_env_override_selects_the_store(tmp_path: Path) -> None:
    store = tmp_path / "elsewhere" / "pki"
    argv = _stub_uv_argv(tmp_path, {"HOME_WARDEN_PKI_STORE": str(store)}, "list")
    assert argv == ["run", "--project", str(REPO), "tiny-pki", "--store", str(store), "list"]


def test_missing_uv_fails_with_a_hint(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("bash", "dirname"):
        (bin_dir / tool).symlink_to(shutil.which(tool) or f"/usr/bin/{tool}")
    env = {"HOME_WARDEN_PKI_STORE": str(tmp_path / "pki"), "PATH": str(bin_dir)}
    result = subprocess.run([str(CLIENT_PKI), "list"], capture_output=True, env=env, text=True, timeout=30)
    assert result.returncode == 1
    assert "install uv" in result.stderr


def test_real_wrapper_creates_and_reads_the_selected_store(tmp_path: Path) -> None:
    store = tmp_path / "pki"
    env = {**os.environ, "HOME_WARDEN_PKI_STORE": str(store)}
    for args in (["init", "--cn", "wrapper test CA", "--key-size", "2048"], ["create", "client", "alice"]):
        result = subprocess.run([str(CLIENT_PKI), *args], capture_output=True, env=env, text=True, timeout=120)
        assert result.returncode == 0, result.stdout + result.stderr
    assert (store / "public" / "ca.crt").is_file()
    listed = subprocess.run(
        [str(CLIENT_PKI), "list", "clients", "--json"], capture_output=True, env=env, text=True, timeout=120
    )
    assert listed.returncode == 0, listed.stdout + listed.stderr
    clients = json.loads(listed.stdout)
    assert [c["cn"] for c in (clients if isinstance(clients, list) else [clients])] == ["alice"]


def test_store_defaults_to_conf_pki_in_the_repo(tmp_path: Path) -> None:
    default_store = REPO / "conf" / "pki"
    argv = _stub_uv_argv(tmp_path, {}, "check", "--quiet")
    assert argv == ["run", "--project", str(REPO), "tiny-pki", "--store", str(default_store), "check", "--quiet"]


def _stub_uv_argv(tmp_path: Path, overrides: dict[str, str], *args: str) -> list[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    record = tmp_path / "uv-argv"
    uv = stubs / "uv"
    uv.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" >"{record}"\n')
    uv.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "HOME_WARDEN_PKI_STORE"}
    env.update(overrides)
    env["PATH"] = f"{stubs}{os.pathsep}{os.environ['PATH']}"
    result = subprocess.run([str(CLIENT_PKI), *args], capture_output=True, env=env, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return record.read_text().splitlines()
