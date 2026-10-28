"""Check de vencimiento de certificados TLS."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from sysdiag.context import CheckContext
from sysdiag.models import CheckResult, Status, classify, worst
from sysdiag.parsers.network import parse_target
from sysdiag.registry import register


def fetch_certificate(host: str, port: int, timeout: float, cafile: str | None = None) -> dict:
    """Conecta por TLS validando la cadena y devuelve el certificado del servidor."""
    context = ssl.create_default_context(cafile=cafile)
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        return tls.getpeercert() or {}


def cert_expiry(cert: dict) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=UTC)


def days_until(expiry: datetime, now: datetime) -> float:
    return round((expiry - now).total_seconds() / 86400, 1)


def _issuer(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                return value
    return ""


@register("tls_certs", category="tls", description="Días hasta el vencimiento de certificados TLS")
def check_tls_certs(ctx: CheckContext) -> CheckResult:
    hosts = ctx.get("hosts", [])
    warn_days = float(ctx.get("warn_days", 30))
    crit_days = float(ctx.get("crit_days", 7))
    timeout = float(ctx.get("connect_timeout", 5))
    if not hosts:
        return CheckResult(Status.OK, "Sin hosts configurados")

    now = ctx.clock()
    items = []
    for target in hosts:
        try:
            host, port = parse_target(target, default_port=443)
            cert = fetch_certificate(host, port, timeout, ctx.get("cafile"))
            expiry = cert_expiry(cert)
        except ssl.SSLCertVerificationError as exc:
            # Vencido, autofirmado o el nombre no coincide: es un problema real del certificado.
            items.append(
                {
                    "host": target,
                    "status": Status.CRIT,
                    "days_left": None,
                    "expires": None,
                    "issuer": "",
                    "error": exc.verify_message or str(exc),
                }
            )
            continue
        except (OSError, ValueError, KeyError) as exc:
            items.append(
                {
                    "host": target,
                    "status": Status.ERROR,
                    "days_left": None,
                    "expires": None,
                    "issuer": "",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        days = days_until(expiry, now)
        items.append(
            {
                "host": target,
                "status": classify(days, warn_days, crit_days, higher_is_worse=False),
                "days_left": days,
                "expires": expiry.date().isoformat(),
                "issuer": _issuer(cert),
            }
        )

    problems = [
        f"{i['host']} ({i['error']})"
        if i.get("error")
        else f"{i['host']} vence en {i['days_left']:.0f} días"
        for i in items
        if i["status"] != Status.OK
    ]
    if problems:
        message = "; ".join(problems)
    else:
        soonest = min(items, key=lambda i: i["days_left"])
        message = (
            f"{len(items)} certificados vigentes, el próximo vence en "
            f"{soonest['days_left']:.0f} días ({soonest['host']})"
        )
    return CheckResult(worst(i["status"] for i in items), message, {"items": items})
