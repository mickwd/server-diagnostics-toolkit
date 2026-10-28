from unittest import mock

import psutil
import pytest

from sysdiag.checks import services
from sysdiag.models import Status
from tests.conftest import load


def _svc(name, status, start_type="automatic", fail=False):
    svc = mock.Mock()
    svc.name.return_value = name
    if fail:
        svc.as_dict.side_effect = psutil.AccessDenied()
    else:
        svc.as_dict.return_value = {
            "name": name,
            "display_name": f"Servicio {name}",
            "status": status,
            "start_type": start_type,
        }
    return svc


@pytest.fixture
def windows_services():
    fake = [
        _svc("EventLog", "running"),
        _svc("Dnscache", "running"),
        _svc("W32Time", "stopped", "manual"),
        _svc("Spooler", "stopped", "automatic"),
        _svc("gupdate", "stopped", "automatic"),
        _svc("Protegido", "", fail=True),
    ]
    # create=True: win_service_iter no existe en psutil para Linux.
    with mock.patch.object(services.psutil, "win_service_iter", create=True, return_value=fake):
        yield


def test_windows_required_services(make_ctx, windows_services):
    ctx = make_ctx("services", os_family="windows", windows=["eventlog", "W32Time", "NoExiste"])
    result = services.check_services(ctx)
    items = {i["service"]: i for i in result.details["items"]}
    assert items["EventLog"]["status"] == Status.OK  # la búsqueda no distingue mayúsculas
    assert items["W32Time"]["status"] == Status.CRIT
    assert items["NoExiste"]["status"] == Status.WARN
    assert result.status == Status.CRIT
    assert "W32Time (stopped)" in result.message


def test_windows_automatic_stopped(make_ctx, windows_services):
    ctx = make_ctx(
        "services",
        os_family="windows",
        windows=["EventLog"],
        windows_check_automatic=True,
    )
    result = services.check_services(ctx)
    names = [i["service"] for i in result.details["items"]]
    assert "Spooler" in names
    assert "gupdate" not in names  # está en la lista de ignorados por defecto
    assert "W32Time" not in names  # es manual
    assert result.status == Status.WARN


def test_linux_services_and_failed_units(make_ctx, fake_executor):
    fake_executor.add(("systemctl", "is-active"), load("systemctl_is_active.txt"), 3)
    fake_executor.add(("systemctl", "list-units"), load("systemctl_failed.txt"))
    ctx = make_ctx("services", linux=["ssh", "cron", "nginx"])
    result = services.check_services(ctx)
    items = {i["service"]: i for i in result.details["items"]}
    assert items["ssh"]["status"] == Status.OK
    assert items["cron"]["state"] == "inactive"
    assert items["nginx"]["status"] == Status.CRIT
    # nginx.service ya está como "nginx": no se duplica; el timer sí aparece.
    assert "nginx.service" not in items
    assert items["certbot-renew.timer"]["status"] == Status.WARN
    assert fake_executor.calls[0] == ["systemctl", "is-active", "ssh", "cron", "nginx"]


def test_linux_all_ok(make_ctx, fake_executor):
    fake_executor.add(("systemctl", "is-active"), "active\n")
    ctx = make_ctx("services", linux=["ssh"], linux_check_failed=False)
    result = services.check_services(ctx)
    assert result.status == Status.OK
    assert result.message == "1 servicios corriendo"


def test_linux_systemctl_missing_output(make_ctx, fake_executor):
    fake_executor.add(("systemctl", "is-active"), "", 1, "System has not been booted with systemd")
    result = services.check_services(make_ctx("services", linux=["ssh"]))
    assert result.status == Status.ERROR


def test_nothing_configured(make_ctx, fake_executor):
    fake_executor.add(("systemctl", "list-units"), "")
    result = services.check_services(make_ctx("services", linux=[]))
    assert result.status == Status.OK
