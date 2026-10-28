"""Carga de configuración YAML con valores por defecto."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "timeout_seconds": 30,
    "max_workers": 16,
    "checks": {
        "dns": {"names": ["google.com", "github.com"], "warn_ms": 300},
        "tcp_ports": {"targets": ["github.com:443", "1.1.1.1:53"], "connect_timeout": 3},
        "ping": {
            "hosts": ["8.8.8.8", "1.1.1.1"],
            "count": 4,
            "timeout_ms": 1000,
            "warn_ms": 100,
            "crit_ms": 300,
            "warn_loss_pct": 10,
            "crit_loss_pct": 50,
        },
        "gateway": {"ping": True, "count": 2},
        "tls_certs": {
            "hosts": ["github.com", "www.google.com"],
            "warn_days": 30,
            "crit_days": 7,
            "connect_timeout": 5,
            "cafile": None,
        },
        "disk": {
            "warn_pct": 80,
            "crit_pct": 90,
            "exclude": [],
            "ignore_fstypes": ["squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660", "udf"],
        },
        "memory": {"warn_pct": 85, "crit_pct": 95},
        "cpu": {
            "warn_pct": 85,
            "crit_pct": 95,
            "sample_seconds": 1.0,
            "warn_load_per_core": 1.5,
            "crit_load_per_core": 3.0,
        },
        "uptime": {"warn_days": 90, "min_minutes": 15},
        "services": {
            "windows": ["EventLog", "Dnscache", "W32Time", "LanmanServer"],
            "linux": ["cron", "ssh"],
            "windows_check_automatic": False,
            "windows_ignore": [
                "gupdate",
                "gupdatem",
                "edgeupdate",
                "MapsBroker",
                "RemoteRegistry",
                "sppsvc",
                "TrustedInstaller",
                "tiledatamodelsvc",
                "WbioSrvc",
                "CDPSvc",
            ],
            "linux_check_failed": True,
        },
        "updates": {
            "timeout_seconds": 300,
            "warn_count": 1,
            "crit_security": 1,
            "max_days_since_patch": 45,
        },
        "recent_errors": {
            "since_hours": 24,
            "max_events": 200,
            "warn_count": 1,
            "crit_count": 25,
            "windows_logs": ["System", "Application"],
            "show_events": 20,
        },
    },
}


class ConfigError(ValueError):
    pass


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Mergea override sobre base sin modificar ninguno. Las listas se reemplazan."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Carga el YAML (si se indica) y lo mergea con los defaults."""
    if path is None:
        return copy.deepcopy(DEFAULTS)
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"no existe el archivo de configuración: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML inválido en {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"la configuración debe ser un mapa YAML: {path}")
    checks = data.get("checks", {})
    if checks is not None and not isinstance(checks, dict):
        raise ConfigError("'checks' debe ser un mapa con una sección por check")
    return deep_merge(DEFAULTS, data)


def check_settings(config: dict[str, Any], name: str) -> dict[str, Any]:
    return dict(config.get("checks", {}).get(name) or {})


def is_enabled(config: dict[str, Any], name: str) -> bool:
    return bool(check_settings(config, name).get("enabled", True))


def check_timeout(config: dict[str, Any], name: str) -> float:
    settings = check_settings(config, name)
    return float(settings.get("timeout_seconds", config.get("timeout_seconds", 30)))
