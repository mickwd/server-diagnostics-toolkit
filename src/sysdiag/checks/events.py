"""Check de errores recientes: Windows Event Log y journald."""

from __future__ import annotations

from collections import Counter

from sysdiag.context import CheckContext
from sysdiag.executor import clean_powershell_error, powershell_args, ps_quote
from sysdiag.models import CheckResult, EventRecord, Status, classify
from sysdiag.parsers.events import parse_journalctl_json, parse_winevent_json
from sysdiag.registry import register


def winevent_script(logs: list[str], hours: int, max_events: int) -> str:
    """Arma el script de Get-WinEvent. Level 1 = Critical, 2 = Error.

    Se usa -InputObject para que ConvertTo-Json siempre devuelva un array,
    incluso con 0 o 1 eventos (en PowerShell 5.1 el pipeline los "desarma").
    """
    log_list = ", ".join(ps_quote(log) for log in logs)
    return f"""
$filter = @{{
    LogName   = @({log_list})
    Level     = 1, 2
    StartTime = (Get-Date).AddHours(-{int(hours)})
}}
try {{
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents {int(max_events)} -ErrorAction Stop
}} catch {{
    # Sin eventos no es un error; cualquier otra falla (ej. EventLog detenido) se propaga.
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }}
    $events = @()
}}
$rows = @($events | ForEach-Object {{
    [pscustomobject]@{{
        TimeCreated  = $_.TimeCreated.ToUniversalTime().ToString('o')
        Id           = $_.Id
        Level        = $_.Level
        ProviderName = $_.ProviderName
        LogName      = $_.LogName
        Message      = $_.Message
    }}
}})
ConvertTo-Json -InputObject $rows -Depth 3 -Compress
"""


def _collect(ctx: CheckContext, hours: int, max_events: int) -> list[EventRecord]:
    if ctx.os_family == "windows":
        logs = list(ctx.get("windows_logs", ["System", "Application"]))
        script = winevent_script(logs, hours, max_events)
        result = ctx.executor.run(powershell_args(script), timeout=120)
        if result.returncode != 0:
            error = clean_powershell_error(result.stderr)
            if "RPC" in error:
                # Get-WinEvent habla con el servicio EventLog por RPC.
                error += " (¿servicio EventLog detenido?)"
            raise RuntimeError(f"Get-WinEvent falló: {error}")
        return parse_winevent_json(result.stdout)

    args = [
        "journalctl",
        "-p",
        "err",
        "--since",
        f"{int(hours)} hours ago",
        "-o",
        "json",
        "--no-pager",
        "-q",
        "-n",
        str(int(max_events)),
    ]
    result = ctx.executor.run(args, timeout=60)
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(f"journalctl falló: {result.stderr.strip()[:300]}")
    return parse_journalctl_json(result.stdout)


@register(
    "recent_errors",
    category="events",
    description="Errores recientes del Event Log / journald, normalizados",
    remote=True,
)
def check_recent_errors(ctx: CheckContext) -> CheckResult:
    hours = int(ctx.get("since_hours", 24))
    max_events = int(ctx.get("max_events", 200))
    events = _collect(ctx, hours, max_events)
    events.sort(key=lambda e: (e.timestamp is not None, e.timestamp), reverse=True)

    by_source = Counter(e.source for e in events)
    critical = sum(1 for e in events if e.level == "critical")
    details = {
        "since_hours": hours,
        "total": len(events),
        "critical": critical,
        "truncated": len(events) >= max_events,
        "top_sources": [{"source": s, "count": c} for s, c in by_source.most_common(10)],
        "items": [e.to_dict() for e in events[: int(ctx.get("show_events", 20))]],
    }
    if not events:
        return CheckResult(Status.OK, f"Sin errores en las últimas {hours} h", details)

    status = classify(len(events), int(ctx.get("warn_count", 1)), int(ctx.get("crit_count", 25)))
    top, top_count = by_source.most_common(1)[0]
    total = f"{len(events)}+" if details["truncated"] else str(len(events))
    message = f"{total} errores en las últimas {hours} h (más frecuente: {top} x{top_count})"
    if critical:
        message += f", {critical} críticos"
    return CheckResult(status, message, details)
