import json
from datetime import UTC, date, datetime

import pytest

from sysdiag.parsers.events import parse_journalctl_json, parse_winevent_json
from sysdiag.parsers.updates import (
    mark_security,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_dnf_security,
    parse_windows_updates,
)
from tests.conftest import load


def test_apt_upgradable():
    updates = parse_apt_upgradable(load("apt_upgradable.txt"))
    assert [u.name for u in updates] == ["curl", "libssl3", "openssl", "tzdata"]
    assert [u.security for u in updates] == [True, True, True, False]
    assert updates[0].version == "7.81.0-1ubuntu1.18"


def test_dnf_check_update_ignores_obsoletes():
    updates = parse_dnf_check_update(load("dnf_check_update.txt"))
    assert [u.name for u in updates] == ["kernel", "openssl-libs", "python3-urllib3", "vim-minimal"]
    assert updates[1].version == "1:3.0.7-25.el9_3"


def test_dnf_security_and_mark():
    names = parse_dnf_security(load("dnf_security.txt"))
    assert names == {"kernel", "openssl-libs"}
    marked = mark_security(parse_dnf_check_update(load("dnf_check_update.txt")), names)
    assert [u.name for u in marked if u.security] == ["kernel", "openssl-libs"]


def test_windows_updates():
    updates, last = parse_windows_updates(load("windows_updates.json"))
    assert len(updates) == 3
    # Severity "Critical" y la categoría en español cuentan como seguridad.
    assert [u.security for u in updates] == [True, False, True]
    assert updates[0].version == "KB5044281"
    assert last == date(2026, 9, 11)


def test_windows_updates_single_object_and_empty():
    updates, last = parse_windows_updates(load("windows_updates_single.json"))
    assert len(updates) == 1
    assert updates[0].security is False
    assert last is None
    assert parse_windows_updates("   ") == ([], None)


def test_journalctl_json():
    events = parse_journalctl_json(load("journalctl.json"))
    assert len(events) == 4  # la línea que no es JSON se ignora
    assert events[0].source == "sshd"
    assert events[0].timestamp == datetime(2026, 10, 26, 7, 33, 20, tzinfo=UTC)
    assert events[1].level == "critical"  # PRIORITY 2
    assert events[2].source == "nginx.service"  # sin SYSLOG_IDENTIFIER usa la unidad
    assert events[3].message.startswith("error: bad bytes")  # MESSAGE como lista de bytes


def test_winevent_array():
    events = parse_winevent_json(load("winevent.json"))
    assert len(events) == 3
    assert events[0].event_id == 7031
    assert "Cola de impresión" in events[0].message
    assert events[0].timestamp == datetime(2026, 10, 27, 21, 14, 5, 123456, tzinfo=UTC)
    assert events[1].level == "critical"
    assert events[2].log == "Application"


def test_winevent_ps51_single_object_with_ms_date():
    events = parse_winevent_json(load("winevent_ps51_single.json"))
    assert len(events) == 1
    assert events[0].timestamp == datetime.fromtimestamp(1793059245, tz=UTC)
    assert "sin mensaje" in events[0].message


def test_winevent_empty_and_offset_timestamp():
    assert parse_winevent_json("") == []
    events = parse_winevent_json('[{"TimeCreated":"2026-10-27T10:00:00-03:00","Level":2}]')
    assert events[0].timestamp == datetime(2026, 10, 27, 13, 0, tzinfo=UTC)
    assert events[0].source == "desconocido"


def test_event_to_dict_truncates_message():
    event = parse_winevent_json('[{"Message":"' + "x" * 500 + '","Level":2}]')[0]
    data = event.to_dict(max_message=50)
    assert len(data["message"]) == 50
    assert data["timestamp"] is None


@pytest.mark.parametrize("bad", ["{not json", "[1, 2"])
def test_winevent_invalid_json_raises(bad):
    with pytest.raises(json.JSONDecodeError):
        parse_winevent_json(bad)
