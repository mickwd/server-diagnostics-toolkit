"""Genera el reporte de ejemplo de docs/ con datos ficticios y deterministas.

Corre el pipeline real (registry -> runner -> report) pero con psutil, sockets,
ssl y los comandos externos mockeados con las salidas de tests/fixtures. Así el
ejemplo no expone datos de ninguna máquina real.

Uso (desde la raíz del repo):
    python docs/generate_sample.py
"""

from __future__ import annotations

import socket
from collections import namedtuple
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from sysdiag import __version__, registry
from sysdiag.config import load_config
from sysdiag.executor import CommandResult
from sysdiag.report import Report, render_html, to_json
from sysdiag.runner import run_checks, select_checks

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
NOW = datetime(2026, 10, 28, 9, 30, tzinfo=UTC)
GIB = 1024**3


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class SampleExecutor:
    """Devuelve salidas de ejemplo según el comando."""

    def __init__(self) -> None:
        self.responses = {
            ("ping", "-c", "4", "-W", "1", "8.8.8.8"): fixture("ping_linux.txt"),
            ("ping", "-c", "4", "-W", "1", "1.1.1.1"): fixture("ping_busybox.txt"),
            ("ping", "-c", "2"): fixture("ping_linux.txt").replace("8.8.8.8", "10.0.0.1"),
            ("ip", "route"): "default via 10.0.0.1 dev eth0 proto static metric 100\n",
            ("systemctl", "is-active"): "active\nactive\nfailed\n",
            ("systemctl", "list-units"): "certbot-renew.timer loaded failed failed Certbot timer\n",
            ("sh", "-c"): "/usr/bin/apt-get\n",
            ("apt", "list"): fixture("apt_upgradable.txt"),
            ("journalctl",): fixture("journalctl.json"),
        }

    def run(self, args: Sequence[str], timeout: float = 30) -> CommandResult:
        for prefix, stdout in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if tuple(args[: len(prefix)]) == prefix:
                return CommandResult(0, stdout, "")
        raise RuntimeError(f"comando sin salida de ejemplo: {args}")


def _fake_tls_context():
    certs = {
        "github.com": "Feb 12 23:59:59 2027 GMT",
        "www.google.com": "Dec 15 08:00:00 2026 GMT",
        "portal.example.com": "Nov 10 12:00:00 2026 GMT",
    }

    def wrap_socket(sock, server_hostname):
        tls = mock.MagicMock()
        tls.__enter__.return_value.getpeercert.return_value = {
            "notAfter": certs[server_hostname],
            "issuer": ((("organizationName", "Example CA"),),),
        }
        return tls

    context = mock.MagicMock()
    context.wrap_socket.side_effect = wrap_socket
    return context


def _fake_connect(address, timeout=None):
    if address[1] == 5432:
        raise TimeoutError
    return mock.MagicMock()


def main() -> None:
    config = load_config(ROOT / "config" / "sysdiag.example.yaml")
    config["checks"]["dns"]["names"] = ["google.com", "github.com", "intranet.example.local"]
    config["checks"]["tls_certs"]["hosts"] = ["github.com", "www.google.com", "portal.example.com"]
    config["checks"]["services"]["linux"] = ["ssh", "cron", "nginx"]
    config["checks"]["recent_errors"]["crit_count"] = 10

    def fake_getaddrinfo(name, *args, **kwargs):
        if name.endswith(".local"):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))]

    Part = namedtuple("Part", "device mountpoint fstype opts")
    Usage = namedtuple("Usage", "total used free percent")
    usages = {
        "/": Usage(50 * GIB, 41 * GIB, 9 * GIB, 82.0),
        "/var/lib/data": Usage(200 * GIB, 60 * GIB, 140 * GIB, 30.0),
    }
    partitions = [
        Part("/dev/sda1", "/", "ext4", "rw"),
        Part("/dev/sdb1", "/var/lib/data", "xfs", "rw"),
    ]

    with (
        mock.patch("sysdiag.checks.network.socket.getaddrinfo", side_effect=fake_getaddrinfo),
        # network y tls comparten el mismo módulo socket: un solo patch para ambos.
        mock.patch("socket.create_connection", side_effect=_fake_connect),
        mock.patch(
            "sysdiag.checks.tls.ssl.create_default_context", return_value=_fake_tls_context()
        ),
        mock.patch("psutil.disk_partitions", return_value=partitions),
        mock.patch("psutil.disk_usage", side_effect=lambda p: usages[p]),
        mock.patch(
            "psutil.virtual_memory",
            return_value=mock.Mock(percent=61.0, total=16 * GIB, available=6.2 * GIB),
        ),
        mock.patch("psutil.swap_memory", return_value=mock.Mock(percent=3.0)),
        mock.patch("psutil.cpu_percent", return_value=23.0),
        mock.patch("psutil.cpu_count", return_value=4),
        mock.patch("psutil.getloadavg", return_value=(0.92, 0.85, 0.80)),
        mock.patch(
            "psutil.boot_time", return_value=(NOW - timedelta(days=12, hours=5)).timestamp()
        ),
    ):
        specs, skipped = select_checks(registry.all_checks(), config, os_family="linux")
        results = run_checks(specs, config, SampleExecutor(), os_family="linux", clock=lambda: NOW)

    # Duraciones fijas para que el archivo generado no cambie entre corridas.
    for result in results:
        result.duration_ms = 1000.0 if result.name == "cpu" else 42.0
        for item in result.details.get("items", []):
            if "ms" in item:
                item["ms"] = 18.4
    report = Report(
        host={
            "hostname": "srv-app-01",
            "fqdn": "srv-app-01.example.local",
            "os": "Linux-5.15.0-105-generic-x86_64-with-glibc2.35 (Ubuntu 22.04.4 LTS)",
            "os_family": "linux",
            "python": "3.12.3",
            "toolkit_version": __version__,
            "mode": "local",
        },
        generated_at=NOW.astimezone(UTC),
        results=results,
        skipped=skipped,
        duration_ms=1180.0,
    )
    data = report.to_dict()
    docs = ROOT / "docs"
    (docs / "sample-report.json").write_text(to_json(data) + "\n", encoding="utf-8")
    (docs / "sample-report.html").write_text(render_html(data), encoding="utf-8")
    print(f"Estado general: {data['overall_status']} -> docs/sample-report.html y .json")


if __name__ == "__main__":
    main()
