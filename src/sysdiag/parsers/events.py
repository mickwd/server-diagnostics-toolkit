"""Normalización de eventos de error de journald y del Event Log de Windows."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from sysdiag.models import EventRecord

# syslog: 0 emerg, 1 alert, 2 crit, 3 err
_JOURNAL_LEVELS = {0: "critical", 1: "critical", 2: "critical", 3: "error"}
# Windows: 1 Critical, 2 Error, 3 Warning
_WINDOWS_LEVELS = {1: "critical", 2: "error", 3: "warning"}

_MS_DATE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")


def _journal_message(value) -> str:
    # journald exporta mensajes no UTF-8 como lista de bytes.
    if isinstance(value, list):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value or "")


def parse_journalctl_json(text: str) -> list[EventRecord]:
    """Parsea `journalctl -o json` (un objeto JSON por línea)."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        timestamp = None
        if entry.get("__REALTIME_TIMESTAMP"):
            micros = int(entry["__REALTIME_TIMESTAMP"])
            timestamp = datetime.fromtimestamp(micros / 1_000_000, tz=UTC)
        priority = int(entry.get("PRIORITY", 3))
        source = (
            entry.get("SYSLOG_IDENTIFIER")
            or entry.get("_SYSTEMD_UNIT")
            or entry.get("_COMM")
            or "desconocido"
        )
        events.append(
            EventRecord(
                timestamp=timestamp,
                level=_JOURNAL_LEVELS.get(priority, "error"),
                source=str(source),
                message=_journal_message(entry.get("MESSAGE")),
                event_id=None,
                log=str(entry.get("_SYSTEMD_UNIT") or "journal"),
            )
        )
    return events


def _parse_windows_time(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, dict):  # PowerShell 5.1 a veces serializa DateTime como objeto
        value = value.get("value") or value.get("DateTime")
        if not value:
            return None
    value = str(value)
    match = _MS_DATE.search(value)
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=UTC)
    # .NET "o" usa 7 decimales; fromisoformat de 3.11 acepta hasta 6.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_winevent_json(text: str) -> list[EventRecord]:
    """Parsea la salida de Get-WinEvent | ConvertTo-Json.

    Acepta un array, un único objeto (PowerShell 5.1 sin -InputObject) o vacío.
    """
    text = text.strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    events = []
    for item in data:
        level_num = item.get("Level")
        level = _WINDOWS_LEVELS.get(int(level_num), "error") if level_num is not None else "error"
        events.append(
            EventRecord(
                timestamp=_parse_windows_time(item.get("TimeCreated")),
                level=level,
                source=str(item.get("ProviderName") or "desconocido"),
                message=str(item.get("Message") or "(sin mensaje: falta la DLL del proveedor)"),
                event_id=int(item["Id"]) if item.get("Id") is not None else None,
                log=str(item.get("LogName") or ""),
            )
        )
    return events
