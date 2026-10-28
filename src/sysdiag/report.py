"""Armado del reporte y exportación a JSON y HTML."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from sysdiag.models import CheckResult, Status, worst
from sysdiag.runner import Skipped


@dataclass(slots=True)
class Report:
    host: dict[str, str]
    generated_at: datetime
    results: list[CheckResult]
    skipped: list[Skipped] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def overall(self) -> Status:
        return worst(r.status for r in self.results)

    @property
    def exit_code(self) -> int:
        return self.overall.exit_code

    def summary(self) -> dict[str, int]:
        counts = Counter(r.status.value for r in self.results)
        return {s.value: counts.get(s.value, 0) for s in Status}

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "host": self.host,
            "overall_status": self.overall.value,
            "exit_code": self.exit_code,
            "summary": self.summary(),
            "duration_ms": round(self.duration_ms, 1),
            "results": [r.to_dict() for r in self.results],
            "skipped": [{"name": s.name, "reason": s.reason} for s in self.skipped],
        }


def to_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("sysdiag", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["status_class"] = lambda s: str(s).lower()
    env.filters["columns"] = _columns
    return env


def _columns(rows: list[dict[str, Any]]) -> list[str]:
    """Unión ordenada de las claves de todas las filas (ej. "error" solo en las que fallan)."""
    columns: dict[str, None] = {}
    for row in rows:
        columns.update(dict.fromkeys(row))
    return list(columns)


def render_html(data: dict[str, Any]) -> str:
    """Renderiza el reporte HTML (autocontenido, sin dependencias externas)."""
    return _environment().get_template("report.html.j2").render(report=data)


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "host"


def write_reports(data: dict[str, Any], output_dir: str | Path, formats: list[str]) -> list[Path]:
    """Escribe el reporte en los formatos pedidos y devuelve las rutas generadas."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(data["generated_at"]).strftime("%Y%m%d-%H%M%S")
    base = f"sysdiag-{_safe(data['host'].get('hostname', 'host'))}-{stamp}"
    paths = []
    if "json" in formats:
        path = output / f"{base}.json"
        path.write_text(to_json(data) + "\n", encoding="utf-8")
        paths.append(path)
    if "html" in formats:
        path = output / f"{base}.html"
        path.write_text(render_html(data), encoding="utf-8")
        paths.append(path)
    return paths
