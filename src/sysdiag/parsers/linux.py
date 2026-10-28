"""Parsers de comandos y archivos de Linux (systemctl, df, /proc)."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence

_VALID_STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading"}


def parse_systemctl_is_active(units: Sequence[str], output: str) -> dict[str, str]:
    """`systemctl is-active a b c` imprime un estado por línea, en el mismo orden.

    Si una unidad no existe imprime "inactive" (o "unknown" en versiones viejas).
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    states = {}
    for index, unit in enumerate(units):
        state = lines[index] if index < len(lines) else "unknown"
        states[unit] = state if state in _VALID_STATES else "unknown"
    return states


def parse_systemctl_failed(output: str) -> list[str]:
    """Parsea `systemctl list-units --state=failed --no-legend --plain`."""
    units = []
    for line in output.splitlines():
        parts = line.replace("●", " ").split()
        if parts and "." in parts[0]:
            units.append(parts[0])
    return units


def parse_df(output: str) -> list[dict]:
    """Parsea `df -P -k`. Devuelve tamaños en bytes y porcentaje de uso."""
    disks = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6 or not parts[1].isdigit():
            continue
        total = int(parts[1]) * 1024
        used = int(parts[2]) * 1024
        free = int(parts[3]) * 1024
        percent = float(parts[4].rstrip("%")) if parts[4].rstrip("%").isdigit() else 0.0
        disks.append(
            {
                "device": parts[0],
                "mountpoint": " ".join(parts[5:]),
                "total": total,
                "used": used,
                "free": free,
                "percent": percent,
            }
        )
    return disks


def parse_meminfo(text: str) -> dict[str, int]:
    """Parsea /proc/meminfo y devuelve valores en bytes."""
    values = {}
    for line in text.splitlines():
        match = re.match(r"^(\w+(?:\(\w+\))?):\s+(\d+)(?:\s+kB)?", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    return values


def memory_percent_from_meminfo(values: dict[str, int]) -> float:
    total = values.get("MemTotal", 0)
    if not total:
        raise ValueError("MemTotal ausente en /proc/meminfo")
    available = values.get("MemAvailable")
    if available is None:  # kernels muy viejos
        available = values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
    return round(100.0 * (total - available) / total, 1)


def parse_loadavg(text: str) -> tuple[float, float, float]:
    parts = text.split()
    return float(parts[0]), float(parts[1]), float(parts[2])


def parse_proc_uptime(text: str) -> float:
    return float(text.split()[0])


def parse_os_release(text: str) -> dict[str, str]:
    data = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            parts = shlex.split(value) if value else [""]
            data[key.strip()] = parts[0] if parts else ""
    return data
