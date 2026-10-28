"""Parser de la salida de ping para Windows (inglés y español) y Linux (iputils/busybox)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

# Respuestas individuales: "time=14ms", "time<1ms", "tiempo=14ms", "time=14.2 ms".
_REPLY_TIME = re.compile(r"(?:time|tiempo)\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)

# Linux: "4 packets transmitted, 4 received, 0% packet loss" (busybox agrega "packets").
_LINUX_SUMMARY = re.compile(
    r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received"
    r".*?(\d+(?:\.\d+)?)%\s+packet loss",
    re.IGNORECASE,
)
# Linux: "rtt min/avg/max/mdev = 13.1/14.2/15.3/0.8 ms" o "round-trip min/avg/max = ...".
_LINUX_RTT = re.compile(r"min/avg/max\S*\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)")

# Windows (independiente del idioma):
#   "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),"
#   "Paquetes: enviados = 4, recibidos = 4, perdidos = 0 (0% perdidos),"
_WIN_SUMMARY = re.compile(r"=\s*(\d+),\s*[^=,]+=\s*(\d+),\s*[^=,]+=\s*(\d+)\s*\((\d+)%")
#   "Minimum = 13ms, Maximum = 15ms, Average = 14ms"
#   "Mínimo = 13ms, Máximo = 15ms, Media = 14ms"
_WIN_RTT = re.compile(r"=\s*(\d+)\s*ms,\s*[^=]+=\s*(\d+)\s*ms,\s*[^=]+=\s*(\d+)\s*ms")

# Respuestas que Windows cuenta como "recibidas" pero en realidad son errores.
_UNREACHABLE = re.compile(r"unreachable|inaccesible|inalcanzable|TTL expired|TTL expir", re.I)


@dataclass(frozen=True, slots=True)
class PingStats:
    sent: int
    received: int
    loss_pct: float
    rtt_min: float | None = None
    rtt_avg: float | None = None
    rtt_max: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _to_float(value: str) -> float:
    return float(value.replace(",", "."))


def parse_ping(output: str) -> PingStats | None:
    """Parsea la salida de ping. Devuelve None si no hay resumen reconocible
    (por ejemplo, el host no resolvió por DNS)."""
    times = [_to_float(m.group(1)) for m in _REPLY_TIME.finditer(output)]

    linux = _LINUX_SUMMARY.search(output)
    if linux:
        sent, received, loss = int(linux.group(1)), int(linux.group(2)), float(linux.group(3))
        rtt = _LINUX_RTT.search(output)
        if rtt:
            rtt_min, rtt_avg, rtt_max = (float(rtt.group(i)) for i in (1, 2, 3))
        elif times:
            rtt_min, rtt_avg, rtt_max = min(times), sum(times) / len(times), max(times)
        else:
            rtt_min = rtt_avg = rtt_max = None
        return PingStats(sent, received, loss, rtt_min, rtt_avg, rtt_max)

    win = _WIN_SUMMARY.search(output)
    if win:
        sent, received = int(win.group(1)), int(win.group(2))
        # Windows cuenta "Destination host unreachable" como respuesta recibida:
        # en ese caso nos quedamos con las respuestas que trajeron tiempo.
        if received > len(times) and _UNREACHABLE.search(output):
            received = len(times)
        loss = round(100.0 * (sent - received) / sent, 1) if sent else 100.0
        rtt = _WIN_RTT.search(output)
        if times:
            rtt_min, rtt_max = min(times), max(times)
            rtt_avg = round(sum(times) / len(times), 1)
        elif rtt and received:
            rtt_min, rtt_max, rtt_avg = (float(rtt.group(i)) for i in (1, 2, 3))
        else:
            rtt_min = rtt_avg = rtt_max = None
        return PingStats(sent, received, loss, rtt_min, rtt_avg, rtt_max)

    return None
