"""Checks de red: DNS, puertos TCP, latencia (ping) y gateway por defecto."""

from __future__ import annotations

import socket
import time

from sysdiag.context import CheckContext
from sysdiag.models import CheckResult, Status, classify, worst
from sysdiag.parsers.network import (
    parse_ip_route_default,
    parse_route_print_default,
    parse_target,
)
from sysdiag.parsers.ping import PingStats, parse_ping
from sysdiag.registry import register


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


@register("dns", category="network", description="Resolución DNS de una lista de nombres")
def check_dns(ctx: CheckContext) -> CheckResult:
    names = ctx.get("names", [])
    warn_ms = float(ctx.get("warn_ms", 300))
    if not names:
        return CheckResult(Status.OK, "Sin nombres configurados")
    items = []
    for name in names:
        start = time.perf_counter()
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            items.append(
                {
                    "name": name,
                    "status": Status.CRIT,
                    "addresses": [],
                    "ms": _elapsed_ms(start),
                    "error": str(exc),
                }
            )
            continue
        elapsed = _elapsed_ms(start)
        addresses = sorted({info[4][0] for info in infos})
        status = Status.WARN if elapsed >= warn_ms else Status.OK
        items.append({"name": name, "status": status, "addresses": addresses, "ms": elapsed})

    failed = [i["name"] for i in items if i["status"] == Status.CRIT]
    slow = [i["name"] for i in items if i["status"] == Status.WARN]
    if failed:
        message = f"No resuelven: {', '.join(failed)}"
    elif slow:
        message = f"Resolución lenta (>= {warn_ms:.0f} ms): {', '.join(slow)}"
    else:
        message = f"{len(items)} nombres resueltos correctamente"
    return CheckResult(worst(i["status"] for i in items), message, {"items": items})


def _probe_tcp(host: str, port: int, timeout: float) -> tuple[Status, str, float]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return Status.OK, "abierto", _elapsed_ms(start)
    except socket.gaierror:
        return Status.CRIT, "no resuelve DNS", _elapsed_ms(start)
    except ConnectionRefusedError:
        # El host responde pero nadie escucha: servicio caído, no un problema de red.
        return Status.CRIT, "rechazado (servicio no escucha)", _elapsed_ms(start)
    except TimeoutError:
        # Sin respuesta: típico de firewall que descarta paquetes o ruta inexistente.
        return Status.CRIT, "timeout (posible firewall)", _elapsed_ms(start)
    except OSError as exc:
        return Status.CRIT, f"error: {exc.strerror or exc}", _elapsed_ms(start)


@register("tcp_ports", category="network", description="Alcance de puertos TCP host:puerto")
def check_tcp_ports(ctx: CheckContext) -> CheckResult:
    targets = ctx.get("targets", [])
    timeout = float(ctx.get("connect_timeout", 3))
    if not targets:
        return CheckResult(Status.OK, "Sin targets configurados")
    items = []
    for target in targets:
        try:
            host, port = parse_target(target)
        except ValueError as exc:
            items.append({"target": target, "status": Status.ERROR, "result": str(exc), "ms": 0})
            continue
        status, result, elapsed = _probe_tcp(host, port, timeout)
        items.append({"target": target, "status": status, "result": result, "ms": elapsed})

    bad = [f"{i['target']}: {i['result']}" for i in items if i["status"] != Status.OK]
    message = f"Sin acceso: {'; '.join(bad)}" if bad else f"{len(items)} puertos accesibles"
    return CheckResult(worst(i["status"] for i in items), message, {"items": items})


def ping_args(os_family: str, host: str, count: int, timeout_ms: int) -> list[str]:
    if os_family == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    return ["ping", "-c", str(count), "-W", str(max(1, round(timeout_ms / 1000))), host]


def run_ping(ctx: CheckContext, host: str, count: int, timeout_ms: int) -> PingStats | None:
    # Margen generoso: count respuestas * timeout por respuesta + arranque.
    budget = count * (timeout_ms / 1000 + 1) + 5
    result = ctx.executor.run(ping_args(ctx.os_family, host, count, timeout_ms), timeout=budget)
    return parse_ping(result.stdout)


def _classify_ping(stats: PingStats, settings: dict) -> Status:
    loss_status = classify(
        stats.loss_pct, settings.get("warn_loss_pct", 10), settings.get("crit_loss_pct", 50)
    )
    if stats.received == 0:
        return Status.CRIT
    rtt_status = Status.OK
    if stats.rtt_avg is not None:
        rtt_status = classify(
            stats.rtt_avg, settings.get("warn_ms", 100), settings.get("crit_ms", 300)
        )
    return worst([loss_status, rtt_status])


@register("ping", category="network", description="Latencia y pérdida de paquetes (ICMP)")
def check_ping(ctx: CheckContext) -> CheckResult:
    hosts = ctx.get("hosts", [])
    count = int(ctx.get("count", 4))
    timeout_ms = int(ctx.get("timeout_ms", 1000))
    if not hosts:
        return CheckResult(Status.OK, "Sin hosts configurados")
    items = []
    for host in hosts:
        stats = run_ping(ctx, host, count, timeout_ms)
        if stats is None:
            items.append(
                {
                    "host": host,
                    "status": Status.CRIT,
                    "loss_pct": 100.0,
                    "rtt_avg": None,
                    "note": "sin respuesta o el nombre no resuelve",
                }
            )
            continue
        items.append(
            {"host": host, "status": _classify_ping(stats, ctx.settings), **stats.to_dict()}
        )

    parts = []
    for item in items:
        if item.get("rtt_avg") is not None:
            parts.append(f"{item['host']} {item['rtt_avg']:.0f} ms/{item['loss_pct']:.0f}% loss")
        else:
            parts.append(f"{item['host']} sin respuesta")
    return CheckResult(worst(i["status"] for i in items), "; ".join(parts), {"items": items})


@register("gateway", category="network", description="Gateway por defecto presente y alcanzable")
def check_gateway(ctx: CheckContext) -> CheckResult:
    if ctx.os_family == "windows":
        result = ctx.executor.run(["route", "print", "-4", "0.0.0.0"], timeout=15)
        gateways = parse_route_print_default(result.stdout)
    else:
        result = ctx.executor.run(["ip", "route", "show", "default"], timeout=15)
        gateways = parse_ip_route_default(result.stdout)

    if not gateways:
        return CheckResult(Status.CRIT, "No hay gateway por defecto configurado", {"items": []})

    primary = gateways[0]
    details = {"items": gateways}
    if not ctx.get("ping", True) or primary["gateway"].lower() in {"on-link", "en", "en vínculo"}:
        return CheckResult(Status.OK, f"Gateway por defecto: {primary['gateway']}", details)

    stats = run_ping(ctx, primary["gateway"], int(ctx.get("count", 2)), 1000)
    details["ping"] = stats.to_dict() if stats else None
    if stats is None or stats.received == 0:
        # Muchos firewalls/routers no responden ICMP: lo marcamos WARN y no CRIT.
        return CheckResult(Status.WARN, f"Gateway {primary['gateway']} no responde a ping", details)
    return CheckResult(
        Status.OK,
        f"Gateway {primary['gateway']} responde ({stats.rtt_avg:.0f} ms)"
        if stats.rtt_avg is not None
        else f"Gateway {primary['gateway']} responde",
        details,
    )
