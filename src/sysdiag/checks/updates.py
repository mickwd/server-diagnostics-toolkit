"""Check de actualizaciones pendientes (Windows Update, apt, dnf/yum)."""

from __future__ import annotations

from sysdiag.context import CheckContext
from sysdiag.executor import clean_powershell_error, powershell_args
from sysdiag.models import CheckResult, PendingUpdate, Status
from sysdiag.parsers.updates import (
    mark_security,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_dnf_security,
    parse_windows_updates,
)
from sysdiag.registry import register

# Consulta la API COM de Windows Update (no instala nada) y la fecha del último hotfix.
WINDOWS_UPDATE_SCRIPT = r"""
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$pending = @(foreach ($u in $result.Updates) {
    [pscustomobject]@{
        Title      = $u.Title
        KB         = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','
        Severity   = $u.MsrcSeverity
        Categories = @($u.Categories | ForEach-Object { $_.Name })
    }
})
$hotfix = Get-HotFix | Where-Object { $_.InstalledOn } |
    Sort-Object InstalledOn -Descending | Select-Object -First 1
$last = $null
if ($hotfix) {
    $last = [pscustomobject]@{
        HotFixID    = $hotfix.HotFixID
        InstalledOn = $hotfix.InstalledOn.ToString('yyyy-MM-dd')
    }
}
[pscustomobject]@{ Pending = $pending; LastHotFix = $last } | ConvertTo-Json -Depth 4 -Compress
"""


def _detect_linux_manager(ctx: CheckContext) -> str | None:
    result = ctx.executor.run(["sh", "-c", "command -v apt-get dnf yum"], timeout=10)
    for line in result.stdout.splitlines():
        name = line.strip().rsplit("/", 1)[-1]
        if name in {"apt-get", "dnf", "yum"}:
            return "apt" if name == "apt-get" else name
    return None


def _linux_updates(ctx: CheckContext, timeout: float) -> tuple[list[PendingUpdate], str]:
    manager = _detect_linux_manager(ctx)
    if manager == "apt":
        # No corre "apt update" (requiere root): usa la caché tal como está.
        result = ctx.executor.run(["apt", "list", "--upgradable"], timeout=timeout)
        return parse_apt_upgradable(result.stdout), "apt"
    if manager in {"dnf", "yum"}:
        result = ctx.executor.run([manager, "-q", "check-update"], timeout=timeout)
        # check-update devuelve 100 si hay updates, 0 si no hay y 1 si hubo error.
        if result.returncode not in (0, 100):
            raise RuntimeError(f"{manager} check-update falló: {result.stderr.strip()[:200]}")
        updates = parse_dnf_check_update(result.stdout)
        security = ctx.executor.run(
            [manager, "-q", "updateinfo", "list", "--security"], timeout=timeout
        )
        return mark_security(updates, parse_dnf_security(security.stdout)), manager
    raise RuntimeError("no se encontró apt, dnf ni yum")


@register(
    "updates",
    category="updates",
    description="Actualizaciones pendientes (Windows Update, apt, dnf/yum)",
    remote=True,
)
def check_updates(ctx: CheckContext) -> CheckResult:
    timeout = float(ctx.get("timeout_seconds", 300)) - 5
    last_patch = None
    if ctx.os_family == "windows":
        result = ctx.executor.run(powershell_args(WINDOWS_UPDATE_SCRIPT), timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(
                f"consulta a Windows Update falló: {clean_powershell_error(result.stderr)}"
            )
        updates, last_patch = parse_windows_updates(result.stdout)
        manager = "windows_update"
    else:
        updates, manager = _linux_updates(ctx, timeout)

    security = [u for u in updates if u.security]
    details: dict = {
        "manager": manager,
        "pending": len(updates),
        "security": len(security),
        "items": [u.to_dict() for u in sorted(updates, key=lambda u: (not u.security, u.name))][
            :50
        ],
    }
    status = Status.OK
    reasons = []
    if len(security) >= int(ctx.get("crit_security", 1)):
        status = Status.CRIT
        reasons.append(f"{len(security)} de seguridad")
    elif len(updates) >= int(ctx.get("warn_count", 1)):
        status = Status.WARN

    if last_patch is not None:
        days = (ctx.clock().date() - last_patch).days
        details["last_patch"] = last_patch.isoformat()
        details["days_since_patch"] = days
        if days > int(ctx.get("max_days_since_patch", 45)):
            reasons.append(f"último parche hace {days} días")
            if status == Status.OK:
                status = Status.WARN

    if not updates and status == Status.OK:
        return CheckResult(Status.OK, "Sistema al día, sin actualizaciones pendientes", details)
    message = f"{len(updates)} actualizaciones pendientes"
    if reasons:
        message += f" ({', '.join(reasons)})"
    return CheckResult(status, message, details)
