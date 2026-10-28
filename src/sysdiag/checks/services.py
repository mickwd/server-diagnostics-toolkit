"""Check de servicios que deberían estar corriendo (Windows y systemd)."""

from __future__ import annotations

import psutil

from sysdiag.context import CheckContext
from sysdiag.models import CheckResult, Status, worst
from sysdiag.parsers.linux import parse_systemctl_failed, parse_systemctl_is_active
from sysdiag.registry import register


def _windows_services() -> dict[str, dict]:
    services = {}
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
        except (psutil.Error, OSError):
            # Servicios protegidos pueden negar el acceso a algunos atributos.
            info = {
                "name": svc.name(),
                "display_name": svc.name(),
                "status": "unknown",
                "start_type": "unknown",
            }
        services[info["name"].lower()] = info
    return services


def _check_windows(ctx: CheckContext) -> CheckResult:
    required = ctx.get("windows", [])
    services = _windows_services()
    items = []
    for name in required:
        info = services.get(name.lower())
        if info is None:
            items.append({"service": name, "status": Status.WARN, "state": "no existe"})
            continue
        state = info.get("status", "unknown")
        items.append(
            {
                "service": info["name"],
                "display_name": info.get("display_name", ""),
                "status": Status.OK if state == "running" else Status.CRIT,
                "state": state,
                "start_type": info.get("start_type", ""),
            }
        )

    if ctx.get("windows_check_automatic", False):
        ignore = {s.lower() for s in ctx.get("windows_ignore", [])}
        listed = {i["service"].lower() for i in items}
        for key, info in sorted(services.items()):
            if key in ignore or key in listed:
                continue
            if info.get("start_type") == "automatic" and info.get("status") != "running":
                items.append(
                    {
                        "service": info["name"],
                        "display_name": info.get("display_name", ""),
                        "status": Status.WARN,
                        "state": info.get("status", "unknown"),
                        "start_type": "automatic",
                    }
                )
    return _summarize(items)


def _check_linux(ctx: CheckContext) -> CheckResult:
    units = list(ctx.get("linux", []))
    items = []
    if units:
        # is-active devuelve != 0 si alguna unidad no está activa; igual imprime todos los estados.
        result = ctx.executor.run(["systemctl", "is-active", *units], timeout=15)
        if not result.stdout.strip() and result.returncode != 0:
            return CheckResult(Status.ERROR, f"systemctl falló: {result.stderr.strip()[:200]}")
        for unit, state in parse_systemctl_is_active(units, result.stdout).items():
            items.append(
                {
                    "service": unit,
                    "status": Status.OK if state == "active" else Status.CRIT,
                    "state": state,
                }
            )
    if ctx.get("linux_check_failed", True):
        result = ctx.executor.run(
            ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"], timeout=15
        )
        listed = {i["service"] for i in items}
        for unit in parse_systemctl_failed(result.stdout):
            if unit not in listed and unit.removesuffix(".service") not in listed:
                items.append({"service": unit, "status": Status.WARN, "state": "failed"})
    return _summarize(items)


def _summarize(items: list[dict]) -> CheckResult:
    if not items:
        return CheckResult(
            Status.OK, "Sin servicios configurados ni unidades en falla", {"items": []}
        )
    bad = [f"{i['service']} ({i['state']})" for i in items if i["status"] != Status.OK]
    if bad:
        message = f"Servicios con problemas: {', '.join(bad)}"
    else:
        message = f"{len(items)} servicios corriendo"
    return CheckResult(worst(i["status"] for i in items), message, {"items": items})


@register(
    "services",
    category="services",
    description="Servicios requeridos detenidos (psutil en Windows, systemctl en Linux)",
    remote=True,
)
def check_services(ctx: CheckContext) -> CheckResult:
    if ctx.os_family == "windows":
        return _check_windows(ctx)
    return _check_linux(ctx)
