"""Enmascarado de datos sensibles antes de adjuntar el reporte a un ticket externo.

Reemplaza hostname, FQDN, usuario actual, IPs de las interfaces locales,
IPs privadas (RFC 1918) y direcciones MAC.
"""

from __future__ import annotations

import getpass
import ipaddress
import re
import socket
from collections.abc import Iterable
from typing import Any

import psutil

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")


class Redactor:
    def __init__(
        self,
        hostnames: Iterable[str] = (),
        users: Iterable[str] = (),
        addresses: Iterable[str] = (),
    ) -> None:
        self._rules: list[tuple[re.Pattern[str], str]] = []
        for values, label in ((hostnames, "<host>"), (users, "<usuario>"), (addresses, "<ip>")):
            for value in sorted({v for v in values if v and len(v) >= 2}, key=len, reverse=True):
                pattern = re.compile(
                    rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])", re.IGNORECASE
                )
                self._rules.append((pattern, label))

    def text(self, value: str) -> str:
        for pattern, label in self._rules:
            value = pattern.sub(label, value)
        value = _MAC.sub("<mac>", value)
        return _IPV4.sub(_mask_private_ip, value)

    def apply(self, data: Any) -> Any:
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, dict):
            return {key: self.apply(value) for key, value in data.items()}
        if isinstance(data, list | tuple):
            return [self.apply(value) for value in data]
        return data


def _mask_private_ip(match: re.Match[str]) -> str:
    try:
        ip = ipaddress.IPv4Address(match.group(1))
    except ipaddress.AddressValueError:
        return match.group(0)
    if ip.is_private and not ip.is_loopback:
        return "<ip>"
    return match.group(0)


def local_redactor() -> Redactor:
    """Construye un Redactor con los datos identificables de este equipo."""
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    hostnames = {hostname, fqdn, fqdn.split(".")[0]}
    try:
        users = {getpass.getuser()}
    except (OSError, KeyError):
        users = set()
    addresses = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                ip = addr.address.split("%")[0]
                if ip not in {"127.0.0.1", "::1"}:
                    addresses.add(ip)
    return Redactor(hostnames, users, addresses)
