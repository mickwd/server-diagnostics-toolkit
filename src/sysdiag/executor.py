"""Ejecución de comandos externos (local o remota) detrás de una interfaz común.

Los checks nunca llaman a subprocess directamente: reciben un executor en el
contexto. Eso permite reutilizar los mismos checks por SSH y mockear todo en
los tests.
"""

from __future__ import annotations

import base64
import html
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class CommandError(RuntimeError):
    """El comando no existe, no se pudo lanzar o superó el timeout."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandExecutor(Protocol):
    def run(self, args: Sequence[str], timeout: float = 30) -> CommandResult: ...


def decode_output(data: bytes) -> str:
    """Decodifica la salida de un proceso.

    Primero intenta UTF-8; si falla y estamos en Windows usa la página de
    códigos OEM de la consola (cp850 en equipos en español), que es la que usan
    herramientas como ping.exe o route.exe.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if sys.platform == "win32":
        try:
            return data.decode("oem", errors="replace")
        except LookupError:  # pragma: no cover - el codec "oem" solo existe en Windows
            pass
    return data.decode("utf-8", errors="replace")


class LocalExecutor:
    """Ejecuta comandos en el equipo local con subprocess."""

    def run(self, args: Sequence[str], timeout: float = 30) -> CommandResult:
        env = None
        kwargs: dict = {}
        if sys.platform == "win32":
            # Evita que se abra una ventana de consola si se ejecuta desde el Programador de tareas.
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            # Forzamos locale C para que la salida de ping, df, etc. sea parseable.
            env = {**os.environ, "LC_ALL": "C"}
        try:
            proc = subprocess.run(
                list(args),
                capture_output=True,
                timeout=timeout,
                check=False,
                env=env,
                **kwargs,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"comando no encontrado: {args[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(f"timeout de {timeout}s ejecutando {args[0]}") from exc
        return CommandResult(
            returncode=proc.returncode,
            stdout=decode_output(proc.stdout or b""),
            stderr=decode_output(proc.stderr or b""),
        )


_PS_PRELUDE = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "$ProgressPreference = 'SilentlyContinue'; "
    "$ErrorActionPreference = 'Stop'; "
)


def powershell_args(script: str) -> list[str]:
    """Arma la línea de comando para correr un script con Windows PowerShell 5.1.

    Se usa -EncodedCommand (UTF-16LE en base64) para no pelear con el quoting
    de cmd/PowerShell, y se fuerza la salida en UTF-8 para no romper acentos.
    """
    encoded = base64.b64encode((_PS_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]


def ps_quote(value: str) -> str:
    """Escapa un string para usarlo como literal entre comillas simples en PowerShell."""
    return "'" + value.replace("'", "''") + "'"


_CLIXML_STRING = re.compile(r'<S S="Error">(.*?)</S>', re.DOTALL)
_CLIXML_ESCAPE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def clean_powershell_error(stderr: str, limit: int = 300) -> str:
    """Convierte el stderr en formato CLIXML de PowerShell en texto legible.

    Al correr con -EncodedCommand y salida redirigida, PowerShell emite los
    errores serializados ("#< CLIXML <Objs ...>"). Nos quedamos con la primera
    línea del mensaje, que es la que sirve para un ticket.
    """
    if "#< CLIXML" not in stderr:
        text = stderr.strip()
    else:
        parts = [
            _CLIXML_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), html.unescape(chunk))
            for chunk in _CLIXML_STRING.findall(stderr)
        ]
        text = "".join(parts).strip()
    first_line = text.splitlines()[0].strip() if text else ""
    return first_line[:limit]
