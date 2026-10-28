"""Registro de checks como plugins.

Cada check se registra con el decorador `@register`. Los checks propios viven
en `sysdiag.checks`; paquetes externos pueden aportar checks declarando un
entry point en el grupo `sysdiag.checks` que apunte al módulo que los define.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points

from sysdiag.context import CheckContext
from sysdiag.models import CheckResult

CheckFunc = Callable[[CheckContext], CheckResult]

CATEGORY_ORDER = ("network", "tls", "system", "services", "updates", "events")
ALL_PLATFORMS = frozenset({"windows", "linux"})


@dataclass(frozen=True, slots=True)
class CheckSpec:
    name: str
    func: CheckFunc
    category: str
    description: str
    platforms: frozenset[str] = ALL_PLATFORMS
    remote: bool = False


_REGISTRY: dict[str, CheckSpec] = {}
_loaded = False


def register(
    name: str,
    *,
    category: str,
    description: str,
    platforms: tuple[str, ...] = ("windows", "linux"),
    remote: bool = False,
) -> Callable[[CheckFunc], CheckFunc]:
    """Registra una función como check.

    `remote=True` indica que el check sabe correr contra un host Linux por SSH
    (solo usa el executor, no psutil ni sockets locales).
    """

    def decorator(func: CheckFunc) -> CheckFunc:
        if name in _REGISTRY:
            raise ValueError(f"check duplicado: {name}")
        _REGISTRY[name] = CheckSpec(
            name=name,
            func=func,
            category=category,
            description=description,
            platforms=frozenset(platforms),
            remote=remote,
        )
        return func

    return decorator


def load_plugins() -> None:
    """Importa los checks incluidos y los plugins externos (una sola vez)."""
    global _loaded
    if _loaded:
        return
    importlib.import_module("sysdiag.checks")
    for ep in entry_points(group="sysdiag.checks"):
        ep.load()
    _loaded = True


def _sort_key(spec: CheckSpec) -> tuple[int, str]:
    try:
        index = CATEGORY_ORDER.index(spec.category)
    except ValueError:
        index = len(CATEGORY_ORDER)
    return index, spec.name


def all_checks() -> list[CheckSpec]:
    load_plugins()
    return sorted(_REGISTRY.values(), key=_sort_key)


def get_check(name: str) -> CheckSpec:
    load_plugins()
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"check desconocido: {name}") from None
