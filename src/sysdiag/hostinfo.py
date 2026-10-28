"""Información del host donde corre el diagnóstico."""

from __future__ import annotations

import os
import platform
import socket

from sysdiag import __version__
from sysdiag.executor import CommandExecutor
from sysdiag.parsers.linux import parse_os_release


def local_os_family() -> str:
    return "windows" if os.name == "nt" else "linux"


def local_host_info() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": platform.platform(),
        "os_family": local_os_family(),
        "python": platform.python_version(),
        "toolkit_version": __version__,
        "mode": "local",
    }


def remote_host_info(executor: CommandExecutor, target: str) -> dict[str, str]:
    hostname = executor.run(["hostname"], timeout=10).stdout.strip() or target
    release = parse_os_release(executor.run(["cat", "/etc/os-release"], timeout=10).stdout)
    kernel = executor.run(["uname", "-r"], timeout=10).stdout.strip()
    return {
        "hostname": hostname,
        "fqdn": hostname,
        "os": f"{release.get('PRETTY_NAME', 'Linux')} (kernel {kernel})".strip(),
        "os_family": "linux",
        "python": platform.python_version(),
        "toolkit_version": __version__,
        "mode": f"remoto (SSH {target})",
    }
