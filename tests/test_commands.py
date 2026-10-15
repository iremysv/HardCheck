"""Bounded subprocess tests execute only synthetic Python snippets."""

import sys
from pathlib import Path

import pytest

from hardcheck import commands


@pytest.mark.parametrize(
    ("script", "timeout", "limit", "expected"),
    [
        ("print('fixture')", 2, 1024, "done"),
        ("print('x' * 10000)", 2, 32, "error"),
        ("import time; time.sleep(2)", 0.05, 1024, "error"),
    ],
)
def test_query_bounds(monkeypatch, script, timeout, limit, expected):
    monkeypatch.setattr(commands, "QUERIES", {"fixture": ("python", ("-c", script))})
    monkeypatch.setattr(commands, "resolve_binary", lambda name: Path(sys.executable))
    assert commands.run_query("fixture", timeout=timeout, limit=limit).state == expected


def test_no_arbitrary_commands_or_path_search(monkeypatch):
    assert commands.run_query("shell-injection").state == "error"
    monkeypatch.setattr(commands, "resolve_binary", lambda name: None)
    assert commands.run_query("nft").state == "missing"


@pytest.mark.parametrize(
    ("owner", "mode", "accepted"),
    [
        (0, 0o755, True),
        (1000, 0o755, False),
        (0, 0o775, False),
    ],
)
def test_binary_trust_checks(monkeypatch, owner, mode, accepted):
    import stat
    from types import SimpleNamespace

    monkeypatch.setattr(commands, "TRUSTED_DIRS", ("/fixture",))
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self: SimpleNamespace(st_uid=owner, st_mode=stat.S_IFREG | mode),
    )
    monkeypatch.setattr(commands.os, "access", lambda *args: True)
    assert (commands.resolve_binary("nft") is not None) == accepted


def test_query_start_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr(commands, "resolve_binary", lambda name: Path("/fixture/nft"))

    def denied(*args, **kwargs):
        raise PermissionError("private command path")

    monkeypatch.setattr(commands.subprocess, "Popen", denied)
    result = commands.run_query("nft")
    assert result.state == "error"
    assert not result.output
