"""Fixtures compartidas: lectura de archivos de ejemplo y un executor falso."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sysdiag.config import DEFAULTS, check_settings
from sysdiag.context import CheckContext
from sysdiag.executor import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeExecutor:
    """Responde según el primer prefijo de comando que coincida y registra las llamadas."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult | Callable] | None = None):
        self.responses = dict(responses or {})
        self.calls: list[list[str]] = []

    def add(self, prefix: tuple[str, ...], stdout: str = "", returncode: int = 0, stderr: str = ""):
        self.responses[prefix] = CommandResult(returncode, stdout, stderr)
        return self

    def run(self, args: Sequence[str], timeout: float = 30) -> CommandResult:
        args = list(args)
        self.calls.append(args)
        for prefix, response in sorted(self.responses.items(), key=lambda kv: -len(kv[0])):
            if tuple(args[: len(prefix)]) == prefix:
                return response(args) if callable(response) else response
        raise AssertionError(f"comando no esperado en el test: {args}")


@pytest.fixture
def fake_executor() -> FakeExecutor:
    return FakeExecutor()


@pytest.fixture
def make_ctx(fake_executor: FakeExecutor):
    def factory(name: str, os_family: str = "linux", remote: bool = False, **overrides):
        settings = check_settings(DEFAULTS, name)
        settings.update(overrides)
        return CheckContext(
            settings=settings,
            os_family=os_family,
            executor=fake_executor,
            remote=remote,
            clock=lambda: FIXED_NOW,
        )

    return factory
