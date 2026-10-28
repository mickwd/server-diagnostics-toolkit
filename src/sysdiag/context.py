"""Contexto que recibe cada check al ejecutarse."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sysdiag.executor import CommandExecutor


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class CheckContext:
    """Todo lo que un check necesita para correr, inyectado para poder testearlo.

    - settings: la sección del YAML correspondiente al check (ya mergeada con defaults).
    - os_family: "windows" o "linux" (del equipo donde se ejecutan los comandos).
    - executor: ejecuta comandos locales o remotos (SSH).
    - remote: True si el check corre contra un host remoto.
    """

    settings: dict[str, Any]
    os_family: str
    executor: CommandExecutor
    remote: bool = False
    clock: Callable[[], datetime] = field(default=utc_now)

    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)
