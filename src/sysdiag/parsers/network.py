"""Parsers de red: gateway por defecto y targets host:puerto."""

from __future__ import annotations

import re

_IP_ROUTE_DEFAULT = re.compile(
    r"^default\s+via\s+(\S+)(?:.*?\sdev\s+(\S+))?(?:.*?\smetric\s+(\d+))?"
)
# "route print -4 0.0.0.0": Destino  Máscara  Gateway  Interfaz  Métrica.
# Se parsean solo las columnas, así que no depende del idioma.
_ROUTE_PRINT_DEFAULT = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$"
)


def parse_ip_route_default(output: str) -> list[dict]:
    """Parsea `ip route show default` (Linux)."""
    gateways = []
    for line in output.splitlines():
        match = _IP_ROUTE_DEFAULT.match(line.strip())
        if match:
            gateways.append(
                {
                    "gateway": match.group(1),
                    "interface": match.group(2) or "",
                    "metric": int(match.group(3)) if match.group(3) else 0,
                }
            )
    return sorted(gateways, key=lambda g: g["metric"])


def parse_route_print_default(output: str) -> list[dict]:
    """Parsea `route print -4 0.0.0.0` (Windows). Ignora la sección de rutas persistentes."""
    gateways = []
    seen = set()
    for line in output.splitlines():
        match = _ROUTE_PRINT_DEFAULT.match(line)
        if not match:
            continue
        gateway, interface, metric = match.group(1), match.group(2), int(match.group(3))
        if (gateway, interface) in seen:
            continue
        seen.add((gateway, interface))
        gateways.append({"gateway": gateway, "interface": interface, "metric": metric})
    return sorted(gateways, key=lambda g: g["metric"])


def parse_target(target: str, default_port: int | None = None) -> tuple[str, int]:
    """Convierte "host:puerto", "[::1]:443" o "host" (con default_port) en (host, puerto)."""
    target = target.strip()
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port_str = rest.lstrip(":")
    elif target.count(":") == 1:
        host, _, port_str = target.partition(":")
    else:
        host, port_str = target, ""
    if not port_str:
        if default_port is None:
            raise ValueError(f"falta el puerto en el target: {target!r}")
        return host, default_port
    port = int(port_str)
    if not 0 < port < 65536:
        raise ValueError(f"puerto fuera de rango en el target: {target!r}")
    return host, port
