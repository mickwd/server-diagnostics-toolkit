"""Tests de reporte (JSON/HTML), redacción, CLI y modo remoto."""

import json
import socket
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest import mock

import pytest
from typer.testing import CliRunner

from sysdiag import cli, redact, remote
from sysdiag.executor import CommandError
from sysdiag.models import CheckResult, Status
from sysdiag.redact import Redactor
from sysdiag.report import Report, render_html, write_reports
from sysdiag.runner import Skipped
from tests.conftest import FakeExecutor, load

HOST = {
    "hostname": "srv-app-01",
    "fqdn": "srv-app-01.corp.local",
    "os": "Linux-6.8",
    "os_family": "linux",
    "python": "3.12.0",
    "toolkit_version": "0.1.0",
    "mode": "local",
}


def _report() -> Report:
    return Report(
        host=HOST,
        generated_at=datetime(2026, 10, 28, 9, 30, tzinfo=UTC),
        results=[
            CheckResult(Status.OK, "todo bien", {"percent": 10.5}, "memory", "system", 3.2),
            CheckResult(
                Status.CRIT,
                "Servicios con problemas: nginx (failed)",
                {
                    "items": [
                        {"service": "ssh", "status": Status.OK, "state": "active"},
                        {"service": "nginx", "status": Status.CRIT, "state": "failed", "note": "x"},
                    ]
                },
                "services",
                "services",
                12.0,
            ),
            CheckResult(
                Status.WARN,
                "<script>alert(1)</script>",
                {"ping": {"loss_pct": 0}, "tags": ["a", "b"]},
                "gateway",
                "network",
                1.0,
            ),
        ],
        skipped=[Skipped("dns", "no soportado en modo remoto")],
        duration_ms=1234.5,
    )


def test_report_dict():
    data = _report().to_dict()
    assert data["overall_status"] == "CRIT"
    assert data["exit_code"] == 2
    assert data["summary"] == {"OK": 1, "WARN": 1, "CRIT": 1, "ERROR": 0}
    assert data["results"][1]["details"]["items"][1]["status"] == "CRIT"
    json.dumps(data)  # serializable


def test_render_html_escapes_and_shows_tables():
    html = render_html(_report().to_dict())
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html
    assert "nginx" in html
    assert "<th>note</th>" in html  # columna presente solo en la segunda fila
    assert "ping.loss_pct" in html
    assert "no soportado en modo remoto" in html
    assert 'class="badge big crit"' in html


def test_write_reports(tmp_path):
    paths = write_reports(_report().to_dict(), tmp_path / "out", ["json", "html"])
    names = sorted(p.name for p in paths)
    assert names == [
        "sysdiag-srv-app-01-20261028-093000.html",
        "sysdiag-srv-app-01-20261028-093000.json",
    ]
    data = json.loads((tmp_path / "out" / names[1]).read_text(encoding="utf-8"))
    assert data["host"]["hostname"] == "srv-app-01"


def test_redactor():
    r = Redactor(hostnames=["SRV-APP-01"], users=["jperez"], addresses=["203.0.113.10"])
    text = (
        "srv-app-01 C:\\Users\\jperez gw 192.168.1.1 pub 203.0.113.10 dns 8.8.8.8 "
        "mac 00:15:5d:01:02:03 lo 127.0.0.1"
    )
    assert r.text(text) == (
        "<host> C:\\Users\\<usuario> gw <ip> pub <ip> dns 8.8.8.8 mac <mac> lo 127.0.0.1"
    )
    assert r.apply({"a": ["srv-app-01", 5, None]}) == {"a": ["<host>", 5, None]}


def test_local_redactor_collects_identifiers():
    addrs = {
        "eth0": [
            SimpleNamespace(family=socket.AF_INET, address="203.0.113.7"),
            SimpleNamespace(family=socket.AF_INET6, address="fe80::1%eth0"),
            SimpleNamespace(family=-1, address="00:11:22:33:44:55"),
        ],
        "lo": [SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")],
    }
    with (
        mock.patch.object(redact.socket, "gethostname", return_value="web01"),
        mock.patch.object(redact.socket, "getfqdn", return_value="web01.example.com"),
        mock.patch.object(redact.getpass, "getuser", return_value="operador"),
        mock.patch.object(redact.psutil, "net_if_addrs", return_value=addrs),
    ):
        r = redact.local_redactor()
    assert r.text("web01.example.com operador 203.0.113.7 fe80::1") == "<host> <usuario> <ip> <ip>"


# --- CLI ---------------------------------------------------------------------

runner = CliRunner()


def _fake_results(specs, config, executor, **kwargs):
    return [CheckResult(Status.WARN, "algo", name=s.name, category=s.category) for s in specs]


def test_cli_list_checks():
    result = runner.invoke(cli.app, ["list-checks"])
    assert result.exit_code == 0
    assert "tls_certs" in result.output
    assert "+ssh" in result.output


def test_cli_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "sysdiag 0.1.0" in result.output


def test_cli_run_writes_reports_and_exit_code(tmp_path):
    with (
        mock.patch.object(cli, "run_checks", side_effect=_fake_results),
        mock.patch.object(cli, "local_host_info", return_value=dict(HOST)),
    ):
        result = runner.invoke(
            cli.app, ["run", "--only", "disk,memory", "--skip", "memory", "-o", str(tmp_path)]
        )
    assert result.exit_code == 1, result.output
    assert "WARN" in result.output
    assert "SKIP" in result.output
    assert len(list(tmp_path.glob("sysdiag-srv-app-01-*.html"))) == 1
    assert len(list(tmp_path.glob("sysdiag-srv-app-01-*.json"))) == 1


def test_cli_run_stdout_json_with_redact(tmp_path):
    fake_redactor = Redactor(hostnames=["srv-app-01"])
    with (
        mock.patch.object(cli, "run_checks", side_effect=_fake_results),
        mock.patch.object(cli, "local_host_info", return_value=dict(HOST)),
        mock.patch.object(cli, "local_redactor", return_value=fake_redactor),
    ):
        result = runner.invoke(cli.app, ["run", "--only", "disk", "--stdout-json", "--redact"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["host"]["hostname"] == "<host>"
    assert [r["name"] for r in data["results"]] == ["disk"]


def test_cli_run_no_checks_and_bad_config(tmp_path):
    result = runner.invoke(cli.app, ["run", "--only", "nada"])
    assert result.exit_code == 3
    bad = tmp_path / "bad.yaml"
    bad.write_text("checks: [1\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["run", "-c", str(bad)])
    assert result.exit_code == 3
    assert "configuración" in result.output


def test_cli_init_config(tmp_path):
    target = tmp_path / "sysdiag.yaml"
    assert runner.invoke(cli.app, ["init-config", str(target)]).exit_code == 0
    assert "tls_certs" in target.read_text(encoding="utf-8")
    assert runner.invoke(cli.app, ["init-config", str(target)]).exit_code == 1
    assert runner.invoke(cli.app, ["init-config", str(target), "--force"]).exit_code == 0


def test_cli_remote_mode(tmp_path, monkeypatch):
    fake = FakeExecutor()
    fake.add(("hostname",), "db01\n").add(("cat", "/etc/os-release"), load("os_release.txt"))
    fake.add(("uname", "-r"), "5.15.0-105-generic\n")
    fake.close = mock.Mock()
    captured = {}

    def fake_run(specs, config, executor, **kwargs):
        captured.update(kwargs, executor=executor, names=[s.name for s in specs])
        return _fake_results(specs, config, executor)

    monkeypatch.setenv("SSH_PASS", "secreto")
    with (
        mock.patch("sysdiag.remote.connect", return_value=fake) as connect,
        mock.patch.object(cli, "run_checks", side_effect=fake_run),
    ):
        result = runner.invoke(
            cli.app,
            ["run", "--remote", "admin@db01", "--password-env", "SSH_PASS", "-o", str(tmp_path)],
        )
    assert result.exit_code == 1, result.output
    assert connect.call_args.kwargs["password"] == "secreto"
    assert captured["remote"] is True
    assert captured["os_family"] == "linux"
    assert "dns" not in captured["names"]
    assert "disk" in captured["names"]
    fake.close.assert_called_once()
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert data["host"]["os"] == "Ubuntu 22.04.4 LTS (kernel 5.15.0-105-generic)"


def test_cli_remote_connection_error():
    with mock.patch("sysdiag.remote.connect", side_effect=CommandError("no se pudo conectar")):
        result = runner.invoke(cli.app, ["run", "--remote", "admin@db01"])
    assert result.exit_code == 3
    assert "no se pudo conectar" in result.output


# --- remoto ------------------------------------------------------------------


def test_ssh_target_parse():
    assert remote.SSHTarget.parse("root@10.0.0.5", port=2222) == remote.SSHTarget(
        "10.0.0.5", "root", 2222
    )
    assert remote.SSHTarget.parse("db01").user is None
    assert str(remote.SSHTarget("db01", "ana")) == "ana@db01:22"
    with pytest.raises(ValueError, match="inválido"):
        remote.SSHTarget.parse("root@")


def _fake_client(stdout: bytes, stderr: bytes = b"", code: int = 0):
    client = mock.Mock()
    out = mock.Mock()
    out.read.return_value = stdout
    out.channel.recv_exit_status.return_value = code
    err = mock.Mock()
    err.read.return_value = stderr
    client.exec_command.return_value = (mock.Mock(), out, err)
    return client


def test_ssh_executor_runs_with_c_locale():
    client = _fake_client(b"active\n")
    result = remote.SSHExecutor(client).run(["systemctl", "is-active", "my unit"], timeout=9)
    assert result.stdout == "active\n"
    client.exec_command.assert_called_once_with("LC_ALL=C systemctl is-active 'my unit'", timeout=9)


def test_ssh_executor_errors():
    with pytest.raises(CommandError, match="no encontrado"):
        remote.SSHExecutor(_fake_client(b"", code=127)).run(["journalctl"])
    client = mock.Mock()
    client.exec_command.side_effect = TimeoutError
    with pytest.raises(CommandError, match="timeout"):
        remote.SSHExecutor(client).run(["df"])


def test_connect_rejects_unknown_hosts_by_default():
    paramiko = pytest.importorskip("paramiko")
    with mock.patch.object(paramiko, "SSHClient") as client_cls:
        client = client_cls.return_value
        executor = remote.connect(remote.SSHTarget("db01", "ana"), key_filename="id_ed25519")
        policy = client.set_missing_host_key_policy.call_args.args[0]
        assert isinstance(policy, paramiko.RejectPolicy)
        assert client.connect.call_args.kwargs["username"] == "ana"
        executor.close()
        client.close.assert_called_once()

        client.connect.side_effect = paramiko.SSHException("Server not found in known_hosts")
        with pytest.raises(CommandError, match="known_hosts"):
            remote.connect(remote.SSHTarget("db02"), accept_unknown_host=True)
        policy = client.set_missing_host_key_policy.call_args.args[0]
        assert isinstance(policy, paramiko.WarningPolicy)
