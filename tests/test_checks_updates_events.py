import base64

import pytest

from sysdiag.checks import events, updates
from sysdiag.models import Status
from tests.conftest import load


def _decoded_script(args: list[str]) -> str:
    return base64.b64decode(args[-1]).decode("utf-16-le")


def test_updates_apt(make_ctx, fake_executor):
    fake_executor.add(("sh", "-c"), "/usr/bin/apt-get\n")
    fake_executor.add(("apt", "list", "--upgradable"), load("apt_upgradable.txt"))
    result = updates.check_updates(make_ctx("updates"))
    assert result.status == Status.CRIT
    assert result.details["manager"] == "apt"
    assert result.details["security"] == 3
    assert result.details["items"][0]["security"] is True
    assert "3 de seguridad" in result.message


def test_updates_dnf(make_ctx, fake_executor):
    fake_executor.add(("sh", "-c"), "/usr/bin/dnf\n/usr/bin/yum\n")
    fake_executor.add(("dnf", "-q", "check-update"), load("dnf_check_update.txt"), 100)
    fake_executor.add(("dnf", "-q", "updateinfo"), load("dnf_security.txt"))
    result = updates.check_updates(make_ctx("updates"))
    assert result.details["manager"] == "dnf"
    assert result.details["pending"] == 4
    assert result.details["security"] == 2


def test_updates_dnf_error(make_ctx, fake_executor):
    fake_executor.add(("sh", "-c"), "/usr/bin/dnf\n")
    fake_executor.add(("dnf", "-q", "check-update"), "", 1, "Error: Failed to download metadata")
    with pytest.raises(RuntimeError, match="metadata"):
        updates.check_updates(make_ctx("updates"))


def test_updates_linux_up_to_date(make_ctx, fake_executor):
    fake_executor.add(("sh", "-c"), "/usr/bin/apt-get\n")
    fake_executor.add(("apt", "list"), "Listing...\n")
    result = updates.check_updates(make_ctx("updates"))
    assert result.status == Status.OK
    assert "al día" in result.message


def test_updates_no_package_manager(make_ctx, fake_executor):
    fake_executor.add(("sh", "-c"), "", 1)
    with pytest.raises(RuntimeError, match="no se encontró"):
        updates.check_updates(make_ctx("updates"))


def test_updates_windows(make_ctx, fake_executor):
    fake_executor.add(("powershell.exe",), load("windows_updates.json"))
    result = updates.check_updates(make_ctx("updates", os_family="windows"))
    assert result.status == Status.CRIT
    assert result.details["last_patch"] == "2026-09-11"
    assert result.details["days_since_patch"] == 47
    assert "último parche hace 47 días" in result.message
    assert "Microsoft.Update.Session" in _decoded_script(fake_executor.calls[0])


def test_updates_windows_only_definitions_is_warn(make_ctx, fake_executor):
    fake_executor.add(("powershell.exe",), load("windows_updates_single.json"))
    result = updates.check_updates(make_ctx("updates", os_family="windows"))
    assert result.status == Status.WARN


def test_updates_windows_failure_has_clean_message(make_ctx, fake_executor):
    fake_executor.add(("powershell.exe",), "", 1, load("powershell_error_clixml.txt"))
    with pytest.raises(RuntimeError, match=r"The RPC server is unavailable$"):
        updates.check_updates(make_ctx("updates", os_family="windows"))


def test_recent_errors_linux(make_ctx, fake_executor):
    fake_executor.add(("journalctl",), load("journalctl.json"))
    result = events.check_recent_errors(make_ctx("recent_errors", warn_count=1, crit_count=10))
    assert result.status == Status.WARN
    assert result.details["total"] == 4
    assert result.details["critical"] == 1
    assert result.details["top_sources"][0] == {"source": "sshd", "count": 2}
    # Ordenados del más nuevo al más viejo.
    assert result.details["items"][0]["source"] == "sshd"
    assert "sshd x2" in result.message
    assert fake_executor.calls[0][:4] == ["journalctl", "-p", "err", "--since"]


def test_recent_errors_linux_none(make_ctx, fake_executor):
    fake_executor.add(("journalctl",), "")
    result = events.check_recent_errors(make_ctx("recent_errors"))
    assert result.status == Status.OK


def test_recent_errors_linux_failure(make_ctx, fake_executor):
    fake_executor.add(("journalctl",), "", 1, "Failed to get journal access")
    with pytest.raises(RuntimeError, match="journalctl"):
        events.check_recent_errors(make_ctx("recent_errors"))


def test_recent_errors_windows_truncated(make_ctx, fake_executor):
    fake_executor.add(("powershell.exe",), load("winevent.json"))
    ctx = make_ctx("recent_errors", os_family="windows", max_events=3, crit_count=3)
    result = events.check_recent_errors(ctx)
    assert result.status == Status.CRIT
    assert result.details["truncated"] is True
    assert result.message.startswith("3+ errores")
    script = _decoded_script(fake_executor.calls[0])
    assert "-MaxEvents 3" in script
    assert "'System', 'Application'" in script


def test_recent_errors_windows_rpc_hint(make_ctx, fake_executor):
    fake_executor.add(("powershell.exe",), "", 1, load("powershell_error_clixml.txt"))
    with pytest.raises(RuntimeError, match="EventLog detenido"):
        events.check_recent_errors(make_ctx("recent_errors", os_family="windows"))


def test_winevent_script_escapes_log_names():
    script = events.winevent_script(["Microsoft-Windows-Foo/Operational", "O'Brien"], 6, 10)
    assert "'O''Brien'" in script
    assert "AddHours(-6)" in script
