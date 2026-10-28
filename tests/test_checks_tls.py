import ssl
from datetime import UTC, datetime
from unittest import mock

import pytest

from sysdiag.checks import tls
from sysdiag.models import Status


def _cert(not_after: str) -> dict:
    return {
        "notAfter": not_after,
        "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
    }


@pytest.fixture
def patched_tls():
    """Mockea socket y ssl: cada host devuelve el certificado configurado en `certs`."""
    certs: dict[str, object] = {}

    def wrap_socket(sock, server_hostname):
        value = certs[server_hostname]
        if isinstance(value, Exception):
            raise value
        tls_sock = mock.MagicMock()
        tls_sock.__enter__.return_value.getpeercert.return_value = value
        return tls_sock

    context = mock.MagicMock()
    context.wrap_socket.side_effect = wrap_socket
    with (
        mock.patch.object(tls.socket, "create_connection", return_value=mock.MagicMock()),
        mock.patch.object(tls.ssl, "create_default_context", return_value=context),
    ):
        yield certs


def test_days_until():
    now = datetime(2026, 10, 28, tzinfo=UTC)
    assert tls.days_until(datetime(2026, 11, 27, tzinfo=UTC), now) == 30.0
    assert tls.cert_expiry(_cert("Nov 27 00:00:00 2026 GMT")) == datetime(2026, 11, 27, tzinfo=UTC)


def test_tls_thresholds(make_ctx, patched_tls):
    patched_tls["ok.example"] = _cert("Jan 26 12:00:00 2027 GMT")
    patched_tls["soon.example"] = _cert("Nov 15 12:00:00 2026 GMT")
    patched_tls["urgent.example"] = _cert("Oct 31 12:00:00 2026 GMT")
    ctx = make_ctx("tls_certs", hosts=["ok.example", "soon.example:443", "urgent.example"])
    result = tls.check_tls_certs(ctx)
    statuses = [i["status"] for i in result.details["items"]]
    assert statuses == [Status.OK, Status.WARN, Status.CRIT]
    assert result.details["items"][0]["issuer"] == "Let's Encrypt"
    assert result.details["items"][2]["days_left"] == 3.0
    assert result.status == Status.CRIT


def test_tls_all_ok_message(make_ctx, patched_tls):
    patched_tls["a.example"] = _cert("Jan 26 12:00:00 2027 GMT")
    result = tls.check_tls_certs(make_ctx("tls_certs", hosts=["a.example"]))
    assert result.status == Status.OK
    assert "próximo vence en 90 días" in result.message


def test_tls_verification_error_is_crit(make_ctx, patched_tls):
    error = ssl.SSLCertVerificationError("certificate verify failed")
    error.verify_message = "certificate has expired"
    patched_tls["expired.example"] = error
    result = tls.check_tls_certs(make_ctx("tls_certs", hosts=["expired.example"]))
    assert result.status == Status.CRIT
    assert "certificate has expired" in result.message


def test_tls_connection_error_is_error(make_ctx):
    with mock.patch.object(tls.socket, "create_connection", side_effect=TimeoutError("timed out")):
        result = tls.check_tls_certs(make_ctx("tls_certs", hosts=["slow.example"]))
    assert result.status == Status.ERROR
    assert "TimeoutError" in result.details["items"][0]["error"]


def test_tls_no_hosts(make_ctx):
    assert tls.check_tls_certs(make_ctx("tls_certs", hosts=[])).status == Status.OK
