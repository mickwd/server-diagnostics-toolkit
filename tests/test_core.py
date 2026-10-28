"""Tests del núcleo: modelos, registry, config, runner y executor."""

import subprocess
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from sysdiag import config as cfg
from sysdiag import executor as executor_mod
from sysdiag import registry
from sysdiag.executor import (
    CommandError,
    LocalExecutor,
    clean_powershell_error,
    decode_output,
    powershell_args,
    ps_quote,
)
from sysdiag.models import CheckResult, Status, classify, worst
from sysdiag.registry import CheckSpec
from sysdiag.runner import run_checks, select_checks
from tests.conftest import FakeExecutor, load

ROOT = Path(__file__).resolve().parents[1]


# --- modelos ---------------------------------------------------------------


def test_worst_prefers_crit_over_error():
    assert worst([]) == Status.OK
    assert worst([Status.OK, Status.WARN]) == Status.WARN
    assert worst([Status.ERROR, Status.CRIT, Status.WARN]) == Status.CRIT
    assert worst([Status.ERROR, Status.WARN]) == Status.ERROR


def test_exit_codes_follow_nagios():
    assert [s.exit_code for s in (Status.OK, Status.WARN, Status.CRIT, Status.ERROR)] == [
        0,
        1,
        2,
        3,
    ]


def test_classify():
    assert classify(50, 80, 90) == Status.OK
    assert classify(80, 80, 90) == Status.WARN
    assert classify(95, 80, 90) == Status.CRIT
    assert classify(40, 30, 7, higher_is_worse=False) == Status.OK
    assert classify(10, 30, 7, higher_is_worse=False) == Status.WARN
    assert classify(-1, 30, 7, higher_is_worse=False) == Status.CRIT


# --- registry ----------------------------------------------------------------


def test_builtin_checks_registered():
    names = [spec.name for spec in registry.all_checks()]
    assert names[:5] == ["dns", "gateway", "ping", "tcp_ports", "tls_certs"]
    assert {"disk", "memory", "cpu", "uptime", "services", "updates", "recent_errors"} <= set(names)
    assert registry.get_check("disk").remote is True
    assert registry.get_check("dns").remote is False


def test_unknown_check_and_duplicates():
    with pytest.raises(KeyError, match="desconocido"):
        registry.get_check("nope")
    with pytest.raises(ValueError, match="duplicado"):
        registry.register("dns", category="network", description="x")(lambda ctx: None)


# --- config ------------------------------------------------------------------


def test_load_config_merges_defaults(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("timeout_seconds: 5\nchecks:\n  disk:\n    warn_pct: 70\n", encoding="utf-8")
    config = cfg.load_config(path)
    assert config["timeout_seconds"] == 5
    assert config["checks"]["disk"]["warn_pct"] == 70
    assert config["checks"]["disk"]["crit_pct"] == 90
    assert cfg.check_timeout(config, "disk") == 5
    assert cfg.check_timeout(config, "updates") == 300


def test_load_config_errors(tmp_path):
    with pytest.raises(cfg.ConfigError, match="no existe"):
        cfg.load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("checks: [1, 2\n", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="YAML inválido"):
        cfg.load_config(bad)
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("hola\n", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="mapa"):
        cfg.load_config(scalar)
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text("checks: [dns]\n", encoding="utf-8")
    with pytest.raises(cfg.ConfigError, match="checks"):
        cfg.load_config(wrong)


def test_sample_config_is_valid_and_in_sync():
    sample = ROOT / "config" / "sysdiag.example.yaml"
    packaged = ROOT / "src" / "sysdiag" / "templates" / "sample-config.yaml"
    assert sample.read_text(encoding="utf-8") == packaged.read_text(encoding="utf-8")
    config = cfg.load_config(sample)
    assert set(config["checks"]) == {spec.name for spec in registry.all_checks()}


# --- runner ------------------------------------------------------------------


def _spec(name, func, **kwargs):
    defaults = {"category": "system", "description": name}
    return CheckSpec(name=name, func=func, **{**defaults, **kwargs})


def test_select_checks_filters():
    specs = [
        _spec("a", lambda c: None, category="network"),
        _spec("b", lambda c: None, remote=True),
        _spec("c", lambda c: None, platforms=frozenset({"windows"})),
        _spec("d", lambda c: None),
    ]
    config = {"checks": {"d": {"enabled": False}}}
    selected, skipped = select_checks(specs, config, os_family="linux", remote=True, skip=["x"])
    assert [s.name for s in selected] == ["b"]
    reasons = {s.name: s.reason for s in skipped}
    assert "remoto" in reasons["a"]
    assert "linux" in reasons["c"]
    assert "deshabilitado" in reasons["d"]

    selected, _ = select_checks(specs, config, os_family="linux", only=["network"])
    assert [s.name for s in selected] == ["a"]
    selected, skipped = select_checks(specs, {}, os_family="windows", skip=["a"])
    assert [s.name for s in selected] == ["b", "c", "d"]
    assert skipped[0].reason == "excluido por línea de comandos"


def test_run_checks_handles_exceptions_and_order():
    def boom(ctx):
        raise ZeroDivisionError("division by zero")

    def failing_command(ctx):
        raise CommandError("comando no encontrado: foo")

    def ok(ctx):
        return CheckResult(Status.OK, f"setting={ctx.get('x')}")

    specs = [_spec("ok", ok), _spec("boom", boom), _spec("cmd", failing_command)]
    config = {"timeout_seconds": 5, "checks": {"ok": {"x": 1}}}
    results = run_checks(specs, config, FakeExecutor(), os_family="linux")
    assert [r.name for r in results] == ["ok", "boom", "cmd"]
    assert results[0].message == "setting=1"
    assert results[0].category == "system"
    assert results[1].status == Status.ERROR
    assert results[1].message == "ZeroDivisionError: division by zero"
    assert results[2].message == "comando no encontrado: foo"
    assert all(r.duration_ms >= 0 for r in results)


def test_run_checks_runs_concurrently_with_timeout():
    release = threading.Event()

    def slow(ctx):
        release.wait(5)
        return CheckResult(Status.OK, "tarde")

    def fast(ctx):
        time.sleep(0.05)
        return CheckResult(Status.OK, "rápido")

    specs = [_spec("slow", slow), _spec("fast1", fast), _spec("fast2", fast)]
    config = {"timeout_seconds": 5, "checks": {"slow": {"timeout_seconds": 0.3}}}
    start = time.monotonic()
    results = run_checks(specs, config, FakeExecutor(), os_family="linux")
    elapsed = time.monotonic() - start
    release.set()
    assert results[0].status == Status.ERROR
    assert "Timeout" in results[0].message
    assert [r.status for r in results[1:]] == [Status.OK, Status.OK]
    assert elapsed < 1.5


def test_run_checks_empty():
    assert run_checks([], {}, FakeExecutor(), os_family="linux") == []


# --- executor ----------------------------------------------------------------


def test_local_executor_success():
    completed = subprocess.CompletedProcess(["x"], 0, b"hola\n", b"")
    with mock.patch.object(executor_mod.subprocess, "run", return_value=completed) as run:
        result = LocalExecutor().run(["echo", "hola"], timeout=7)
    assert result.ok
    assert result.stdout == "hola\n"
    assert run.call_args.kwargs["timeout"] == 7
    assert run.call_args.args[0] == ["echo", "hola"]


def test_local_executor_errors():
    with (
        mock.patch.object(executor_mod.subprocess, "run", side_effect=FileNotFoundError),
        pytest.raises(CommandError, match="no encontrado"),
    ):
        LocalExecutor().run(["noexiste"])
    timeout = subprocess.TimeoutExpired(["ping"], 3)
    with (
        mock.patch.object(executor_mod.subprocess, "run", side_effect=timeout),
        pytest.raises(CommandError, match="timeout"),
    ):
        LocalExecutor().run(["ping"], timeout=3)


def test_decode_output_fallback():
    assert decode_output("Mínimo".encode()) == "Mínimo"
    # cp850: "í" = 0xA1. No es UTF-8 válido: no debe explotar.
    assert decode_output(b"M\xa1nimo").startswith("M")


def test_powershell_args_roundtrip():
    args = powershell_args("Write-Output 'ñandú'")
    assert args[:2] == ["powershell.exe", "-NoProfile"]
    import base64

    script = base64.b64decode(args[-1]).decode("utf-16-le")
    assert script.endswith("Write-Output 'ñandú'")
    assert "OutputEncoding" in script


def test_ps_quote_and_clixml():
    assert ps_quote("O'Brien") == "'O''Brien'"
    assert clean_powershell_error(load("powershell_error_clixml.txt")) == (
        "Get-WinEvent : The RPC server is unavailable"
    )
    assert clean_powershell_error("  simple error\nsegunda línea") == "simple error"
    assert clean_powershell_error("") == ""
