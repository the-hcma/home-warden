"""Tests for app.catalog_render_cli."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.catalog_render_cli import main


def test_cli_help_exits_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "app.catalog_render_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert "catalog" in proc.stdout.lower()


def test_cli_missing_catalog_file_exits_2(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["render-catalog", "--services-json", str(tmp_path / "missing.json")])
    assert main() == 2
    assert "missing catalog file" in capsys.readouterr().err


def test_cli_malformed_catalog_exits_2_no_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    # A shape-valid catalog missing a field the renderer (not load_catalog)
    # requires -- no server_name -- used to raise a raw KeyError that
    # escaped main()'s except clause as an uncaught traceback (exit 1).
    services_json = tmp_path / "services.json"
    services_json.write_text(
        '{"services": [{"name": "s", "kind": "proxy", "upstream": {"host": "backend.internal", "port": 8080}}]}'
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["render-catalog", "--services-json", str(services_json), "--certs-live-dir", str(tmp_path / "certs")],
    )
    assert main() == 2
    err = capsys.readouterr().err
    assert "render-catalog: malformed catalog" in err
    assert "Traceback" not in err


def test_cli_renders_to_output_file(tmp_path: Path, monkeypatch) -> None:
    services_json = tmp_path / "services.json"
    services_json.write_text(
        '{"services": [{"name": "s", "server_name": "s.example.com", "kind": "proxy", '
        '"upstream": {"host": "backend.internal", "port": 8080}}]}'
    )
    output = tmp_path / "rendered.conf"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "render-catalog",
            "--services-json",
            str(services_json),
            "--certs-live-dir",
            str(tmp_path / "certs"),
            "--output",
            str(output),
        ],
    )
    assert main() == 0
    rendered = output.read_text()
    assert "server_name s.example.com;" in rendered
    assert "proxy_pass http://backend.internal:8080/;" in rendered


def test_cli_prints_to_stdout_by_default(tmp_path: Path, monkeypatch, capsys) -> None:
    services_json = tmp_path / "services.json"
    services_json.write_text(
        '{"services": [{"name": "s", "server_name": "s.example.com", "kind": "proxy", '
        '"upstream": {"host": "backend.internal", "port": 8080}}]}'
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "render-catalog",
            "--services-json",
            str(services_json),
            "--certs-live-dir",
            str(tmp_path / "certs"),
        ],
    )
    assert main() == 0
    assert "server_name s.example.com;" in capsys.readouterr().out
