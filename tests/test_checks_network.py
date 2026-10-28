import socket
from unittest import mock

from sysdiag.checks import network
from sysdiag.models import Status
from tests.conftest import load


def _addrinfo(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_dns_ok_and_failure(make_ctx):
    def fake_getaddrinfo(name, *args, **kwargs):
        if name == "noexiste.invalid":
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return _addrinfo("140.82.112.3")

    ctx = make_ctx("dns", names=["github.com", "noexiste.invalid"])
    with mock.patch.object(network.socket, "getaddrinfo", side_effect=fake_getaddrinfo):
        result = network.check_dns(ctx)
    assert result.status == Status.CRIT
    assert "noexiste.invalid" in result.message
    assert result.details["items"][0]["addresses"] == ["140.82.112.3"]


def test_dns_slow_is_warn(make_ctx):
    ctx = make_ctx("dns", names=["github.com"], warn_ms=0)
    with mock.patch.object(network.socket, "getaddrinfo", return_value=_addrinfo("1.2.3.4")):
        result = network.check_dns(ctx)
    assert result.status == Status.WARN


def test_dns_without_names(make_ctx):
    assert network.check_dns(make_ctx("dns", names=[])).status == Status.OK


def test_tcp_ports_distinguishes_failures(make_ctx):
    def fake_connect(address, timeout):
        _host, port = address
        if port == 443:
            return mock.MagicMock()
        if port == 5432:
            raise ConnectionRefusedError
        if port == 3389:
            raise TimeoutError
        raise socket.gaierror

    ctx = make_ctx(
        "tcp_ports",
        targets=["web:443", "db:5432", "rdp:3389", "nohost:22", "malformado"],
    )
    with mock.patch.object(network.socket, "create_connection", side_effect=fake_connect):
        result = network.check_tcp_ports(ctx)

    by_target = {i["target"]: i for i in result.details["items"]}
    assert by_target["web:443"]["status"] == Status.OK
    assert "rechazado" in by_target["db:5432"]["result"]
    assert "firewall" in by_target["rdp:3389"]["result"]
    assert "DNS" in by_target["nohost:22"]["result"]
    assert by_target["malformado"]["status"] == Status.ERROR
    assert result.status == Status.CRIT


def test_tcp_ports_generic_oserror(make_ctx):
    ctx = make_ctx("tcp_ports", targets=["x:1"])
    error = OSError(113, "No route to host")
    with mock.patch.object(network.socket, "create_connection", side_effect=error):
        result = network.check_tcp_ports(ctx)
    assert "No route to host" in result.details["items"][0]["result"]


def test_ping_args_per_platform():
    assert network.ping_args("windows", "h", 4, 1000) == ["ping", "-n", "4", "-w", "1000", "h"]
    assert network.ping_args("linux", "h", 2, 500) == ["ping", "-c", "2", "-W", "1", "h"]


def test_ping_linux_ok_and_loss(make_ctx, fake_executor):
    fake_executor.add(("ping", "-c", "4", "-W", "1", "8.8.8.8"), load("ping_linux.txt"), 0)
    fake_executor.add(("ping", "-c", "4", "-W", "1", "10.0.0.99"), load("ping_linux_loss.txt"), 1)
    result = network.check_ping(make_ctx("ping", hosts=["8.8.8.8", "10.0.0.99"]))
    items = result.details["items"]
    assert items[0]["status"] == Status.OK
    assert items[1]["status"] == Status.CRIT
    assert result.status == Status.CRIT
    assert "10.0.0.99 sin respuesta" in result.message


def test_ping_windows_spanish_loss_is_warn(make_ctx, fake_executor):
    fake_executor.add(("ping", "-n"), load("ping_windows_es.txt"))
    result = network.check_ping(make_ctx("ping", os_family="windows", hosts=["1.1.1.1"]))
    # 25% de pérdida supera warn (10) pero no crit (50).
    assert result.status == Status.WARN


def test_ping_high_latency_is_crit(make_ctx, fake_executor):
    fake_executor.add(("ping",), load("ping_windows_en.txt"))
    ctx = make_ctx("ping", os_family="windows", hosts=["8.8.8.8"], warn_ms=5, crit_ms=10)
    assert network.check_ping(ctx).status == Status.CRIT


def test_ping_unparseable_output(make_ctx, fake_executor):
    fake_executor.add(("ping",), load("ping_windows_unknown_host.txt"), 1)
    result = network.check_ping(make_ctx("ping", os_family="windows", hosts=["noexiste"]))
    assert result.status == Status.CRIT
    assert result.details["items"][0]["note"]


def test_gateway_linux_responds(make_ctx, fake_executor):
    fake_executor.add(("ip", "route", "show", "default"), load("ip_route_default.txt"))
    fake_executor.add(("ping",), load("ping_linux.txt"))
    result = network.check_gateway(make_ctx("gateway"))
    assert result.status == Status.OK
    assert "192.168.1.1" in result.message
    assert fake_executor.calls[-1][-1] == "192.168.1.1"


def test_gateway_windows_no_icmp_is_warn(make_ctx, fake_executor):
    fake_executor.add(("route", "print"), load("route_print_es.txt"))
    fake_executor.add(("ping",), load("ping_windows_unreachable.txt"), 1)
    result = network.check_gateway(make_ctx("gateway", os_family="windows"))
    assert result.status == Status.WARN


def test_gateway_missing_is_crit(make_ctx, fake_executor):
    fake_executor.add(("ip", "route"), "")
    assert network.check_gateway(make_ctx("gateway")).status == Status.CRIT


def test_gateway_without_ping(make_ctx, fake_executor):
    fake_executor.add(("ip", "route"), load("ip_route_default.txt"))
    result = network.check_gateway(make_ctx("gateway", ping=False))
    assert result.status == Status.OK
    assert len(fake_executor.calls) == 1
