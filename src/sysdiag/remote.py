"""Modo remoto: ejecuta los checks contra un host Linux por SSH (paramiko).

Solo corren los checks marcados con `remote=True`, que obtienen todo a
través del executor (systemctl, journalctl, df, /proc, apt/dnf).
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sysdiag.executor import CommandError, CommandResult


@dataclass(frozen=True, slots=True)
class SSHTarget:
    host: str
    user: str | None = None
    port: int = 22

    @classmethod
    def parse(cls, value: str, port: int = 22) -> SSHTarget:
        user, sep, host = value.rpartition("@")
        if not host:
            raise ValueError(f"host remoto inválido: {value!r}")
        return cls(host=host, user=user if sep else None, port=port)

    def __str__(self) -> str:
        prefix = f"{self.user}@" if self.user else ""
        return f"{prefix}{self.host}:{self.port}"


class SSHExecutor:
    """Executor que corre los comandos en el host remoto.

    Fuerza LC_ALL=C para que la salida sea parseable sin importar el idioma
    del servidor.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def run(self, args: Sequence[str], timeout: float = 30) -> CommandResult:
        command = "LC_ALL=C " + shlex.join(args)
        try:
            _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read()
            err = stderr.read()
            code = stdout.channel.recv_exit_status()
        except TimeoutError as exc:
            raise CommandError(f"timeout de {timeout}s ejecutando {args[0]} por SSH") from exc
        except OSError as exc:
            raise CommandError(f"error SSH ejecutando {args[0]}: {exc}") from exc
        if code == 127:
            raise CommandError(f"comando no encontrado en el host remoto: {args[0]}")
        return CommandResult(
            code, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
        )

    def close(self) -> None:
        self._client.close()


def connect(
    target: SSHTarget,
    *,
    key_filename: str | None = None,
    password: str | None = None,
    accept_unknown_host: bool = False,
    timeout: float = 10,
) -> SSHExecutor:
    """Abre la conexión SSH. Por defecto rechaza hosts que no estén en known_hosts."""
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise CommandError(
            "el modo remoto necesita paramiko: pip install 'server-diagnostics-toolkit[remote]'"
        ) from exc

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if accept_unknown_host:
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            target.host,
            port=target.port,
            username=target.user,
            key_filename=key_filename,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
    except (paramiko.SSHException, OSError) as exc:
        client.close()
        raise CommandError(f"no se pudo conectar a {target}: {exc}") from exc
    return SSHExecutor(client)
