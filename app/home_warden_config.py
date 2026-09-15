"""XDG config loader for home-warden's operator-managed settings (#68)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

BACKEND_LOOPBACK_HOST = "127.0.0.1"
BACKEND_LOOPBACK_PORT = 8090
CONFIG_FILENAME = "config.toml"
CONFIG_SUBDIR = "home-warden"


@dataclass(frozen=True)
class HomeWardenConfig:
    fqdn: str = ""


def build_web_ui_catalog_service(config: HomeWardenConfig) -> dict | None:
    fqdn = config.fqdn.strip()
    if not fqdn:
        return None
    return {
        "forward_host_header": True,
        "kind": "proxy",
        "name": "home-warden-web-ui",
        "server_name": fqdn,
        "upstream": {
            "host": BACKEND_LOOPBACK_HOST,
            "path": "/",
            "port": BACKEND_LOOPBACK_PORT,
            "scheme": "http",
        },
    }


def config_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    base_dir = Path(xdg_config_home) if xdg_config_home else Path.home() / ".config"
    return base_dir / CONFIG_SUBDIR / CONFIG_FILENAME


def load_config(path: Path | None = None) -> HomeWardenConfig:
    resolved_path = config_path(path)
    if not resolved_path.is_file():
        return HomeWardenConfig()
    try:
        with resolved_path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError):
        return HomeWardenConfig()
    if not isinstance(data, dict):
        return HomeWardenConfig()
    fqdn = data.get("fqdn", "")
    if not isinstance(fqdn, str):
        return HomeWardenConfig()
    return HomeWardenConfig(fqdn=fqdn.strip())
