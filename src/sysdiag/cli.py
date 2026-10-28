"""Interfaz de línea de comandos: `sysdiag`."""

from __future__ import annotations

import os
import time
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer

from sysdiag import __version__, registry
from sysdiag.config import ConfigError, load_config
from sysdiag.context import utc_now
from sysdiag.executor import CommandError, LocalExecutor
from sysdiag.hostinfo import local_host_info, local_os_family, remote_host_info
from sysdiag.models import Status
from sysdiag.redact import local_redactor
from sysdiag.report import Report, to_json, write_reports
from sysdiag.runner import run_checks, select_checks

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Toolkit de diagnóstico para servidores Windows y Linux.",
)

_COLORS = {
    Status.OK: typer.colors.GREEN,
    Status.WARN: typer.colors.YELLOW,
    Status.CRIT: typer.colors.RED,
    Status.ERROR: typer.colors.MAGENTA,
}


def _split(values: list[str] | None) -> list[str]:
    items: list[str] = []
    for value in values or []:
        items.extend(v.strip() for v in value.split(",") if v.strip())
    return items


def _print_results(report: Report) -> None:
    width = max((len(r.name) for r in report.results), default=10)
    for result in report.results:
        badge = typer.style(f"{result.status.value:<5}", fg=_COLORS[result.status], bold=True)
        typer.echo(f"  {badge}  {result.name:<{width}}  {result.message}")
    for skipped in report.skipped:
        typer.echo(typer.style(f"  SKIP   {skipped.name:<{width}}  {skipped.reason}", dim=True))
    overall = report.overall
    typer.echo(
        "\nEstado general: "
        + typer.style(overall.value, fg=_COLORS[overall], bold=True)
        + f" (exit code {overall.exit_code})"
    )


@app.command()
def run(
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Archivo YAML de configuración.")
    ] = None,
    only: Annotated[
        list[str] | None, typer.Option("--only", help="Checks o categorías a correr (coma).")
    ] = None,
    skip: Annotated[
        list[str] | None, typer.Option("--skip", help="Checks o categorías a omitir (coma).")
    ] = None,
    output_dir: Annotated[
        Path, typer.Option("--output-dir", "-o", help="Carpeta donde guardar los reportes.")
    ] = Path("reports"),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="html, json o ambos (default).")
    ] = None,
    stdout_json: Annotated[
        bool,
        typer.Option("--stdout-json", help="Imprime el JSON por stdout y no escribe archivos."),
    ] = False,
    redact: Annotated[
        bool, typer.Option("--redact", help="Enmascara hostname, usuario, IPs privadas y MACs.")
    ] = False,
    remote: Annotated[
        str | None, typer.Option("--remote", help="Host Linux remoto por SSH: usuario@host.")
    ] = None,
    port: Annotated[int, typer.Option("--port", help="Puerto SSH.")] = 22,
    key: Annotated[Path | None, typer.Option("--key", help="Clave privada SSH.")] = None,
    password_env: Annotated[
        str | None,
        typer.Option("--password-env", help="Variable de entorno con la contraseña SSH."),
    ] = None,
    accept_unknown_host: Annotated[
        bool,
        typer.Option("--accept-unknown-host", help="Acepta hosts que no estén en known_hosts."),
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No imprime resultados.")] = False,
) -> None:
    """Corre la batería de checks y genera el reporte. El exit code refleja el peor estado."""
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        typer.echo(f"Error de configuración: {exc}", err=True)
        raise typer.Exit(3) from exc

    executor = LocalExecutor()
    ssh = None
    if remote:
        from sysdiag.remote import SSHTarget, connect

        try:
            target = SSHTarget.parse(remote, port=port)
            password = os.environ.get(password_env) if password_env else None
            ssh = connect(
                target,
                key_filename=str(key) if key else None,
                password=password,
                accept_unknown_host=accept_unknown_host,
            )
        except (ValueError, CommandError) as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(3) from exc
        executor = ssh
        os_family = "linux"
        host = remote_host_info(ssh, str(target))
    else:
        os_family = local_os_family()
        host = local_host_info()

    try:
        specs, skipped = select_checks(
            registry.all_checks(),
            cfg,
            os_family=os_family,
            remote=bool(remote),
            only=_split(only),
            skip=_split(skip),
        )
        if not specs:
            typer.echo("No hay checks para ejecutar con esos filtros.", err=True)
            raise typer.Exit(3)
        if not quiet and not stdout_json:
            typer.echo(f"sysdiag {__version__} · {host['hostname']} · {len(specs)} checks\n")
        start = time.perf_counter()
        results = run_checks(specs, cfg, executor, os_family=os_family, remote=bool(remote))
        report = Report(
            host=host,
            generated_at=utc_now().astimezone(),
            results=results,
            skipped=skipped,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    finally:
        if ssh is not None:
            ssh.close()

    data = report.to_dict()
    if redact:
        data = local_redactor().apply(data)

    if stdout_json:
        typer.echo(to_json(data))
        raise typer.Exit(report.exit_code)

    if not quiet:
        _print_results(report)
    selected_formats = [f.lower() for f in _split(formats)] or ["html", "json"]
    for path in write_reports(data, output_dir, selected_formats):
        if not quiet:
            typer.echo(f"Reporte: {path}")
    raise typer.Exit(report.exit_code)


@app.command("list-checks")
def list_checks() -> None:
    """Lista los checks disponibles."""
    for spec in registry.all_checks():
        platforms = "/".join(sorted(spec.platforms))
        remote = " +ssh" if spec.remote else ""
        tags = f"[{platforms}{remote}]"
        typer.echo(f"{spec.name:<14} {spec.category:<9} {tags:<22} {spec.description}")


@app.command("init-config")
def init_config(
    path: Annotated[Path, typer.Argument(help="Destino del archivo.")] = Path("sysdiag.yaml"),
    force: Annotated[bool, typer.Option("--force", help="Sobrescribe si existe.")] = False,
) -> None:
    """Genera un archivo de configuración de ejemplo."""
    if path.exists() and not force:
        typer.echo(f"{path} ya existe (usá --force para sobrescribir)", err=True)
        raise typer.Exit(1)
    sample = files("sysdiag").joinpath("templates/sample-config.yaml").read_text(encoding="utf-8")
    path.write_text(sample, encoding="utf-8")
    typer.echo(f"Configuración de ejemplo escrita en {path}")


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[bool, typer.Option("--version", help="Muestra la versión.")] = False,
) -> None:
    if version:
        typer.echo(f"sysdiag {__version__}")
        raise typer.Exit(0)
