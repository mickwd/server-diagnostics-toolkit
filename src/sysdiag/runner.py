"""Ejecución concurrente de los checks con timeout por check."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sysdiag import config as cfg
from sysdiag.context import CheckContext, utc_now
from sysdiag.executor import CommandExecutor
from sysdiag.models import CheckResult, Status
from sysdiag.registry import CheckSpec


@dataclass(frozen=True, slots=True)
class Skipped:
    name: str
    reason: str


def select_checks(
    specs: Iterable[CheckSpec],
    config: dict[str, Any],
    *,
    os_family: str,
    remote: bool = False,
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> tuple[list[CheckSpec], list[Skipped]]:
    """Filtra los checks según plataforma, modo remoto, config y flags del CLI."""
    only_set, skip_set = set(only), set(skip)
    selected, skipped = [], []
    for spec in specs:
        if only_set and spec.name not in only_set and spec.category not in only_set:
            continue
        if spec.name in skip_set or spec.category in skip_set:
            skipped.append(Skipped(spec.name, "excluido por línea de comandos"))
        elif not cfg.is_enabled(config, spec.name):
            skipped.append(Skipped(spec.name, "deshabilitado en la configuración"))
        elif os_family not in spec.platforms:
            skipped.append(Skipped(spec.name, f"no aplica a {os_family}"))
        elif remote and not spec.remote:
            skipped.append(Skipped(spec.name, "no soportado en modo remoto"))
        else:
            selected.append(spec)
    return selected, skipped


def _execute(spec: CheckSpec, ctx: CheckContext) -> CheckResult:
    start = time.perf_counter()
    try:
        result = spec.func(ctx)
    except RuntimeError as exc:
        # Fallas esperables (comando inexistente, timeout, salida con error): mensaje limpio.
        result = CheckResult(Status.ERROR, str(exc))
    except Exception as exc:  # un check roto no debe tirar abajo el reporte completo
        result = CheckResult(Status.ERROR, f"{type(exc).__name__}: {exc}")
    duration = (time.perf_counter() - start) * 1000
    return replace(result, name=spec.name, category=spec.category, duration_ms=duration)


def run_checks(
    specs: list[CheckSpec],
    config: dict[str, Any],
    executor: CommandExecutor,
    *,
    os_family: str,
    remote: bool = False,
    clock: Callable[[], datetime] = utc_now,
) -> list[CheckResult]:
    """Corre los checks en paralelo y devuelve los resultados en el orden recibido.

    Cada check tiene su propio deadline (timeout_seconds global o por check).
    Si se vence, el resultado es ERROR y el hilo queda huérfano: Python no
    permite matar hilos, por eso todos los comandos externos y sockets usan
    además sus propios timeouts.
    """
    if not specs:
        return []
    workers = max(1, min(len(specs), int(config.get("max_workers", 16))))
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sysdiag")
    started = time.monotonic()
    pending: list[tuple[CheckSpec, Future, float, float]] = []
    for spec in specs:
        ctx = CheckContext(
            settings=cfg.check_settings(config, spec.name),
            os_family=os_family,
            executor=executor,
            remote=remote,
            clock=clock,
        )
        timeout = cfg.check_timeout(config, spec.name)
        pending.append((spec, pool.submit(_execute, spec, ctx), started + timeout, timeout))

    results = []
    for spec, future, deadline, timeout in pending:
        try:
            results.append(future.result(timeout=max(0.0, deadline - time.monotonic())))
        except FutureTimeout:
            future.cancel()
            results.append(
                CheckResult(
                    Status.ERROR,
                    f"Timeout: el check no terminó en {timeout:.0f}s",
                    name=spec.name,
                    category=spec.category,
                    duration_ms=timeout * 1000,
                )
            )
    pool.shutdown(wait=False, cancel_futures=True)
    return results
