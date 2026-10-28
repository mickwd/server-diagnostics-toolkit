"""Parsers de actualizaciones pendientes: apt, dnf/yum y Windows Update."""

from __future__ import annotations

import json
import re
from datetime import date

from sysdiag.models import PendingUpdate

# "openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: ...]"
_APT_LINE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<source>\S+)\s+(?P<version>\S+)\s+\S+\s+\[upgradable"
)

# "openssl-libs.x86_64    1:3.0.7-25.el9_3    baseos"
_DNF_LINE = re.compile(
    r"^(?P<name>[\w.+-]+)\.(?P<arch>[\w]+)\s+(?P<version>\S+)\s+(?P<repo>\S+)\s*$"
)
_DNF_SECTION_END = re.compile(r"^(Obsoleting Packages|Security:|Last metadata)", re.I)

# "RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64"
_DNF_SECURITY_LINE = re.compile(r"^\S+\s+\S*Sec\.?\s+(?P<nevra>\S+)$", re.I)
_NEVRA = re.compile(r"^(?P<name>.+?)-(?:\d+:)?[^-]+-[^-]+\.(?P<arch>[^.]+)$")


def parse_apt_upgradable(output: str) -> list[PendingUpdate]:
    """Parsea `apt list --upgradable`. Marca como seguridad lo que viene de *-security."""
    updates = []
    for line in output.splitlines():
        match = _APT_LINE.match(line.strip())
        if not match:
            continue
        source = match.group("source")
        updates.append(
            PendingUpdate(
                name=match.group("name"),
                version=match.group("version"),
                security="-security" in source,
                source=source,
            )
        )
    return updates


def parse_dnf_check_update(output: str) -> list[PendingUpdate]:
    """Parsea `dnf -q check-update` (o yum). Ignora la sección "Obsoleting Packages"."""
    updates = []
    for line in output.splitlines():
        if _DNF_SECTION_END.match(line.strip()):
            break
        match = _DNF_LINE.match(line.strip())
        if match:
            updates.append(
                PendingUpdate(
                    name=match.group("name"),
                    version=match.group("version"),
                    source=match.group("repo"),
                )
            )
    return updates


def parse_dnf_security(output: str) -> set[str]:
    """Parsea `dnf -q updateinfo list --security` y devuelve los nombres de paquete."""
    names = set()
    for line in output.splitlines():
        match = _DNF_SECURITY_LINE.match(line.strip())
        if not match:
            continue
        nevra = _NEVRA.match(match.group("nevra"))
        if nevra:
            names.add(nevra.group("name"))
    return names


def mark_security(updates: list[PendingUpdate], security_names: set[str]) -> list[PendingUpdate]:
    return [
        PendingUpdate(u.name, u.version, u.name in security_names or u.security, u.source)
        for u in updates
    ]


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_security(item: dict) -> bool:
    if item.get("Severity"):
        return True
    categories = " ".join(str(c) for c in _as_list(item.get("Categories")))
    return bool(re.search(r"security|seguridad", categories, re.I))


def parse_windows_updates(text: str) -> tuple[list[PendingUpdate], date | None]:
    """Parsea el JSON que genera el script de Windows Update (COM + Get-HotFix).

    Formato esperado:
    {"Pending": [...], "LastHotFix": {"HotFixID": ..., "InstalledOn": "yyyy-MM-dd"}}.
    PowerShell 5.1 serializa un array de un solo elemento como objeto: se normaliza.
    """
    text = text.strip()
    if not text:
        return [], None
    data = json.loads(text)
    updates = []
    for item in _as_list(data.get("Pending")):
        kb = item.get("KB") or ""
        updates.append(
            PendingUpdate(
                name=item.get("Title") or kb or "(sin título)",
                version=kb,
                security=_is_security(item),
                source="Windows Update",
            )
        )
    last = None
    hotfix = data.get("LastHotFix")
    if isinstance(hotfix, dict) and hotfix.get("InstalledOn"):
        last = date.fromisoformat(str(hotfix["InstalledOn"])[:10])
    return updates, last
