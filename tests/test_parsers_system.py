import pytest

from sysdiag.parsers.linux import (
    memory_percent_from_meminfo,
    parse_df,
    parse_loadavg,
    parse_meminfo,
    parse_os_release,
    parse_proc_uptime,
    parse_systemctl_failed,
    parse_systemctl_is_active,
)
from sysdiag.parsers.network import (
    parse_ip_route_default,
    parse_route_print_default,
    parse_target,
)
from tests.conftest import load


def test_systemctl_is_active_keeps_order():
    states = parse_systemctl_is_active(["ssh", "cron", "nginx"], load("systemctl_is_active.txt"))
    assert states == {"ssh": "active", "cron": "inactive", "nginx": "failed"}


def test_systemctl_is_active_missing_lines_are_unknown():
    assert parse_systemctl_is_active(["a", "b"], "active\n") == {"a": "active", "b": "unknown"}
    assert parse_systemctl_is_active(["a"], "garbage\n") == {"a": "unknown"}


def test_systemctl_failed():
    assert parse_systemctl_failed(load("systemctl_failed.txt")) == [
        "nginx.service",
        "certbot-renew.timer",
    ]
    assert parse_systemctl_failed("● foo.service loaded failed failed Foo\n") == ["foo.service"]
    assert parse_systemctl_failed("") == []


def test_df():
    disks = parse_df(load("df_posix.txt"))
    assert [d["mountpoint"] for d in disks] == ["/", "/boot/efi", "/var/lib/data"]
    root = disks[0]
    assert root["percent"] == 91.0
    assert root["total"] == 51474912 * 1024


def test_meminfo_and_percent():
    values = parse_meminfo(load("meminfo.txt"))
    assert values["MemTotal"] == 8040516 * 1024
    assert memory_percent_from_meminfo(values) == pytest.approx(85.0, abs=0.1)


def test_meminfo_without_memavailable():
    values = {"MemTotal": 1000, "MemFree": 100, "Buffers": 50, "Cached": 50}
    assert memory_percent_from_meminfo(values) == 80.0
    with pytest.raises(ValueError, match="MemTotal"):
        memory_percent_from_meminfo({})


def test_loadavg_and_uptime():
    assert parse_loadavg("0.52 0.58 0.59 1/389 12345\n") == (0.52, 0.58, 0.59)
    assert parse_proc_uptime("350735.47 234388.90\n") == 350735.47


def test_os_release():
    assert parse_os_release(load("os_release.txt"))["PRETTY_NAME"] == "Ubuntu 22.04.4 LTS"


def test_ip_route_default_sorted_by_metric():
    gateways = parse_ip_route_default(load("ip_route_default.txt"))
    assert gateways[0] == {"gateway": "192.168.1.1", "interface": "eth0", "metric": 100}
    assert len(gateways) == 2


def test_route_print_ignores_persistent_routes():
    gateways = parse_route_print_default(load("route_print_es.txt"))
    assert gateways == [{"gateway": "192.168.1.1", "interface": "192.168.1.50", "metric": 25}]


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("github.com:443", ("github.com", 443)),
        ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
        ("10.0.0.5:22", ("10.0.0.5", 22)),
    ],
)
def test_parse_target(target, expected):
    assert parse_target(target) == expected


def test_parse_target_default_port_and_errors():
    assert parse_target("example.com", default_port=443) == ("example.com", 443)
    with pytest.raises(ValueError, match="falta el puerto"):
        parse_target("example.com")
    with pytest.raises(ValueError, match="fuera de rango"):
        parse_target("example.com:70000")
