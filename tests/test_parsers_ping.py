import pytest

from sysdiag.parsers.ping import parse_ping
from tests.conftest import load


def test_windows_english():
    stats = parse_ping(load("ping_windows_en.txt"))
    assert stats is not None
    assert (stats.sent, stats.received, stats.loss_pct) == (4, 4, 0.0)
    assert (stats.rtt_min, stats.rtt_avg, stats.rtt_max) == (13, 14, 15)


def test_windows_spanish_with_timeout():
    stats = parse_ping(load("ping_windows_es.txt"))
    assert stats is not None
    assert (stats.sent, stats.received) == (4, 3)
    assert stats.loss_pct == 25.0
    assert stats.rtt_min == 19
    assert stats.rtt_max == 23
    assert stats.rtt_avg == 21.0


def test_windows_destination_unreachable_is_not_a_reply():
    # Windows cuenta "Destination host unreachable" como recibido con 0% de pérdida.
    stats = parse_ping(load("ping_windows_unreachable.txt"))
    assert stats is not None
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.rtt_avg is None


def test_windows_unknown_host_returns_none():
    assert parse_ping(load("ping_windows_unknown_host.txt")) is None


def test_linux_iputils():
    stats = parse_ping(load("ping_linux.txt"))
    assert stats is not None
    assert (stats.sent, stats.received, stats.loss_pct) == (4, 4, 0.0)
    assert stats.rtt_avg == pytest.approx(14.2)


def test_linux_total_loss():
    stats = parse_ping(load("ping_linux_loss.txt"))
    assert stats is not None
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.rtt_avg is None


def test_busybox():
    stats = parse_ping(load("ping_busybox.txt"))
    assert stats is not None
    assert (stats.sent, stats.received) == (2, 2)
    assert stats.rtt_avg == pytest.approx(9.958)


def test_windows_sub_millisecond_and_comma_decimal():
    output = (
        "Reply from 10.0.0.1: bytes=32 time<1ms TTL=128\n"
        "Reply from 10.0.0.1: bytes=32 tiempo=1,5ms TTL=128\n"
        "    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
    )
    stats = parse_ping(output)
    assert stats is not None
    assert stats.rtt_min == 1.0
    assert stats.rtt_max == 1.5


def test_garbage_returns_none():
    assert parse_ping("") is None
    assert parse_ping("ping: unknown host") is None
