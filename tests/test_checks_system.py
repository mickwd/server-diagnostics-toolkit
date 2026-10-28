from collections import namedtuple
from datetime import timedelta
from unittest import mock

import pytest

from sysdiag.checks import system
from sysdiag.models import Status
from tests.conftest import FIXED_NOW, load

Partition = namedtuple("Partition", "device mountpoint fstype opts")
Usage = namedtuple("Usage", "total used free percent")
GIB = 1024**3


@pytest.fixture
def fake_disks():
    partitions = [
        Partition("C:\\", "C:\\", "NTFS", "rw,fixed"),
        Partition("D:\\", "D:\\", "NTFS", "rw,fixed"),
        Partition("E:\\", "E:\\", "", "cdrom"),
        Partition("tmpfs", "/run", "tmpfs", "rw"),
        Partition("F:\\", "F:\\", "NTFS", "rw,removable"),
    ]
    usages = {
        "C:\\": Usage(100 * GIB, 92 * GIB, 8 * GIB, 92.0),
        "D:\\": Usage(500 * GIB, 100 * GIB, 400 * GIB, 20.0),
    }

    def disk_usage(path):
        if path not in usages:
            raise PermissionError("device not ready")
        return usages[path]

    with (
        mock.patch.object(system.psutil, "disk_partitions", return_value=partitions),
        mock.patch.object(system.psutil, "disk_usage", side_effect=disk_usage),
    ):
        yield


def test_disk_local(make_ctx, fake_disks):
    result = system.check_disk(make_ctx("disk", os_family="windows"))
    assert result.status == Status.CRIT
    assert [i["mountpoint"] for i in result.details["items"]] == ["C:\\", "D:\\"]
    assert "C:\\ al 92%" in result.message


def test_disk_exclude(make_ctx, fake_disks):
    result = system.check_disk(make_ctx("disk", os_family="windows", exclude=["c:\\"]))
    assert result.status == Status.OK
    assert "1 particiones OK" in result.message


def test_disk_remote_uses_df(make_ctx, fake_executor):
    fake_executor.add(("df", "-P", "-k"), load("df_posix.txt"))
    result = system.check_disk(make_ctx("disk", remote=True))
    assert result.status == Status.CRIT
    assert "-x" in fake_executor.calls[0]


def test_disk_none_found(make_ctx):
    with mock.patch.object(system.psutil, "disk_partitions", return_value=[]):
        assert system.check_disk(make_ctx("disk")).status == Status.ERROR


def test_memory_local(make_ctx):
    vm = mock.Mock(percent=88.0, total=16 * GIB, available=2 * GIB)
    with (
        mock.patch.object(system.psutil, "virtual_memory", return_value=vm),
        mock.patch.object(system.psutil, "swap_memory", return_value=mock.Mock(percent=10.0)),
    ):
        result = system.check_memory(make_ctx("memory"))
    assert result.status == Status.WARN
    assert result.details["available_gib"] == 2.0


def test_memory_remote(make_ctx, fake_executor):
    fake_executor.add(("cat", "/proc/meminfo"), load("meminfo.txt"))
    result = system.check_memory(make_ctx("memory", remote=True))
    assert result.status == Status.WARN  # 85.0% >= warn 85
    assert result.details["swap_percent"] == 50.0


def test_cpu_local(make_ctx):
    with (
        mock.patch.object(system.psutil, "cpu_percent", return_value=97.0) as cpu_percent,
        mock.patch.object(system.psutil, "cpu_count", return_value=8),
        mock.patch.object(system.psutil, "getloadavg", return_value=(7.9, 6.0, 5.0)),
    ):
        result = system.check_cpu(make_ctx("cpu", sample_seconds=0.1))
    cpu_percent.assert_called_once_with(interval=0.1)
    assert result.status == Status.CRIT
    assert result.details["load_avg"] == [7.9, 6.0, 5.0]


def test_cpu_local_without_loadavg(make_ctx):
    with (
        mock.patch.object(system.psutil, "cpu_percent", return_value=10.0),
        mock.patch.object(system.psutil, "cpu_count", return_value=None),
        mock.patch.object(system.psutil, "getloadavg", side_effect=OSError),
    ):
        result = system.check_cpu(make_ctx("cpu"))
    assert result.status == Status.OK
    assert "load_avg" not in result.details


def test_cpu_remote_load_per_core(make_ctx, fake_executor):
    fake_executor.add(("cat", "/proc/loadavg"), "6.40 5.10 4.00 3/400 999\n")
    fake_executor.add(("nproc",), "4\n")
    result = system.check_cpu(make_ctx("cpu", remote=True))
    assert result.details["load_per_core"] == 1.6
    assert result.status == Status.WARN


@pytest.mark.parametrize(
    ("uptime", "status", "text"),
    [
        (timedelta(minutes=5), Status.WARN, "Reinicio reciente"),
        (timedelta(days=10), Status.OK, "Uptime 10d"),
        (timedelta(days=200), Status.WARN, "Sin reiniciar"),
    ],
)
def test_uptime_local(make_ctx, uptime, status, text):
    boot = (FIXED_NOW - uptime).timestamp()
    with mock.patch.object(system.psutil, "boot_time", return_value=boot):
        result = system.check_uptime(make_ctx("uptime"))
    assert result.status == status
    assert text in result.message
    assert "boot_time" in result.details


def test_uptime_remote(make_ctx, fake_executor):
    fake_executor.add(("cat", "/proc/uptime"), "90061.5 1000.0\n")
    result = system.check_uptime(make_ctx("uptime", remote=True))
    assert result.details["human"] == "1d 1h 1m"
    assert result.status == Status.OK
