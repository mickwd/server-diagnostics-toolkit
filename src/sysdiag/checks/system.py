"""Checks de sistema: disco, memoria, CPU y uptime.

En modo local se usa psutil. En modo remoto (Linux por SSH) se leen
`df` y archivos de /proc con los parsers puros.
"""

from __future__ import annotations

from datetime import UTC, datetime

import psutil

from sysdiag.context import CheckContext
from sysdiag.models import CheckResult, Status, classify, worst
from sysdiag.parsers.linux import (
    memory_percent_from_meminfo,
    parse_df,
    parse_loadavg,
    parse_meminfo,
    parse_proc_uptime,
)
from sysdiag.registry import register

GIB = 1024**3


def _gib(value: float) -> float:
    return round(value / GIB, 1)


def _local_disks(ignore_fstypes: set[str]) -> list[dict]:
    disks = []
    for part in psutil.disk_partitions(all=False):
        if not part.fstype or part.fstype.lower() in ignore_fstypes or "cdrom" in part.opts:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            # Unidades no listas (lectoras, discos removibles) o sin permisos.
            continue
        disks.append(
            {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            }
        )
    return disks


def _remote_disks(ctx: CheckContext, ignore_fstypes: set[str]) -> list[dict]:
    args = ["df", "-P", "-k"]
    for fstype in sorted(ignore_fstypes):
        args += ["-x", fstype]
    return parse_df(ctx.executor.run(args, timeout=15).stdout)


@register("disk", category="system", description="Uso de disco por partición", remote=True)
def check_disk(ctx: CheckContext) -> CheckResult:
    warn, crit = float(ctx.get("warn_pct", 80)), float(ctx.get("crit_pct", 90))
    ignore = {f.lower() for f in ctx.get("ignore_fstypes", [])}
    exclude = {e.lower() for e in ctx.get("exclude", [])}
    disks = _remote_disks(ctx, ignore) if ctx.remote else _local_disks(ignore)
    disks = [d for d in disks if d["mountpoint"].lower() not in exclude]
    if not disks:
        return CheckResult(Status.ERROR, "No se encontraron particiones para revisar")

    items = []
    for disk in disks:
        items.append(
            {
                "mountpoint": disk["mountpoint"],
                "device": disk["device"],
                "status": classify(disk["percent"], warn, crit),
                "percent": disk["percent"],
                "free_gib": _gib(disk["free"]),
                "total_gib": _gib(disk["total"]),
            }
        )
    status = worst(i["status"] for i in items)
    fullest = max(items, key=lambda i: i["percent"])
    message = (
        f"{fullest['mountpoint']} al {fullest['percent']:.0f}% ({fullest['free_gib']} GiB libres)"
    )
    if status == Status.OK:
        message = f"{len(items)} particiones OK; la más llena: {message}"
    return CheckResult(status, message, {"items": items})


@register("memory", category="system", description="Uso de memoria RAM", remote=True)
def check_memory(ctx: CheckContext) -> CheckResult:
    warn, crit = float(ctx.get("warn_pct", 85)), float(ctx.get("crit_pct", 95))
    if ctx.remote:
        values = parse_meminfo(ctx.executor.run(["cat", "/proc/meminfo"], timeout=10).stdout)
        percent = memory_percent_from_meminfo(values)
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        swap_total = values.get("SwapTotal", 0)
        swap_pct = (
            round(100 * (swap_total - values.get("SwapFree", 0)) / swap_total, 1)
            if swap_total
            else 0.0
        )
    else:
        vm = psutil.virtual_memory()
        percent, total, available = vm.percent, vm.total, vm.available
        swap_pct = psutil.swap_memory().percent
    details = {
        "percent": percent,
        "total_gib": _gib(total),
        "available_gib": _gib(available),
        "swap_percent": swap_pct,
    }
    return CheckResult(
        classify(percent, warn, crit),
        f"Memoria al {percent:.0f}% "
        f"({details['available_gib']} de {details['total_gib']} GiB disponibles)",
        details,
    )


@register("cpu", category="system", description="Uso de CPU y load average", remote=True)
def check_cpu(ctx: CheckContext) -> CheckResult:
    if ctx.remote:
        load = parse_loadavg(ctx.executor.run(["cat", "/proc/loadavg"], timeout=10).stdout)
        cores = int(ctx.executor.run(["nproc"], timeout=10).stdout.strip() or 1)
        per_core = round(load[0] / cores, 2)
        status = classify(
            per_core,
            float(ctx.get("warn_load_per_core", 1.5)),
            float(ctx.get("crit_load_per_core", 3.0)),
        )
        return CheckResult(
            status,
            f"Load 1m {load[0]:.2f} en {cores} cores ({per_core} por core)",
            {"load_avg": list(load), "cores": cores, "load_per_core": per_core},
        )

    percent = psutil.cpu_percent(interval=float(ctx.get("sample_seconds", 1.0)))
    cores = psutil.cpu_count() or 1
    details = {"percent": percent, "cores": cores}
    try:
        load = psutil.getloadavg()
        details["load_avg"] = [round(x, 2) for x in load]
    except (AttributeError, OSError):
        pass
    status = classify(percent, float(ctx.get("warn_pct", 85)), float(ctx.get("crit_pct", 95)))
    return CheckResult(status, f"CPU al {percent:.0f}% ({cores} cores)", details)


def _format_uptime(seconds: float) -> str:
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    return f"{days}d {hours}h {minutes}m"


@register(
    "uptime",
    category="system",
    description="Uptime: reinicios inesperados o sin reiniciar hace mucho",
    remote=True,
)
def check_uptime(ctx: CheckContext) -> CheckResult:
    now = ctx.clock()
    if ctx.remote:
        seconds = parse_proc_uptime(ctx.executor.run(["cat", "/proc/uptime"], timeout=10).stdout)
        boot = None
    else:
        boot = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
        seconds = (now - boot).total_seconds()
    details = {"seconds": int(seconds), "human": _format_uptime(seconds)}
    if boot:
        details["boot_time"] = boot.isoformat()

    min_minutes = float(ctx.get("min_minutes", 15))
    warn_days = float(ctx.get("warn_days", 90))
    if seconds < min_minutes * 60:
        return CheckResult(Status.WARN, f"Reinicio reciente: uptime {details['human']}", details)
    if seconds > warn_days * 86400:
        # Un servidor sin reiniciar hace meses casi seguro tiene parches de kernel pendientes.
        return CheckResult(
            Status.WARN, f"Sin reiniciar hace {details['human']} (> {warn_days:.0f} días)", details
        )
    return CheckResult(Status.OK, f"Uptime {details['human']}", details)
