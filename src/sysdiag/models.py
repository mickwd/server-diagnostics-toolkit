"""Modelos de datos compartidos por todos los checks."""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


class Status(enum.StrEnum):
    """Estado de un check.

    El orden de severidad (para calcular el "peor" estado) es
    OK < WARN < ERROR < CRIT: un CRIT real pesa más que un check que no pudo
    ejecutarse. El exit code sigue la convención de Nagios/Icinga
    (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN).
    """

    OK = "OK"
    WARN = "WARN"
    CRIT = "CRIT"
    ERROR = "ERROR"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self]


_SEVERITY = {Status.OK: 0, Status.WARN: 1, Status.ERROR: 2, Status.CRIT: 3}
_EXIT_CODES = {Status.OK: 0, Status.WARN: 1, Status.CRIT: 2, Status.ERROR: 3}


def worst(statuses: Iterable[Status]) -> Status:
    """Devuelve el estado más severo de la lista (OK si está vacía)."""
    return max(statuses, key=lambda s: s.severity, default=Status.OK)


def classify(value: float, warn: float, crit: float, *, higher_is_worse: bool = True) -> Status:
    """Clasifica un valor numérico contra umbrales de warning y crítico."""
    if higher_is_worse:
        if value >= crit:
            return Status.CRIT
        if value >= warn:
            return Status.WARN
        return Status.OK
    if value <= crit:
        return Status.CRIT
    if value <= warn:
        return Status.WARN
    return Status.OK


@dataclass(slots=True)
class CheckResult:
    """Resultado de un check. El runner completa name, category y duration_ms."""

    status: Status
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    name: str = ""
    category: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["duration_ms"] = round(self.duration_ms, 1)
        return data


@dataclass(slots=True, frozen=True)
class EventRecord:
    """Evento de error normalizado (Windows Event Log o journald)."""

    timestamp: datetime | None
    level: str
    source: str
    message: str
    event_id: int | None = None
    log: str = ""

    def to_dict(self, max_message: int = 300) -> dict[str, Any]:
        message = " ".join(self.message.split())
        if len(message) > max_message:
            message = message[: max_message - 3] + "..."
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "source": self.source,
            "event_id": self.event_id,
            "log": self.log,
            "message": message,
        }


@dataclass(slots=True, frozen=True)
class PendingUpdate:
    """Actualización pendiente normalizada (apt, dnf/yum o Windows Update)."""

    name: str
    version: str = ""
    security: bool = False
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
