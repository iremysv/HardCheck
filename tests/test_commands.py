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


def test_query_does_not_inherit_private_environment(monkeypatch):
    monkeypatch.setenv("PRIVATE_FIXTURE_VALUE", "fixture")
    script = (
        "import os; print(os.environ.get('PRIVATE_FIXTURE_VALUE', 'absent')); "
        "print(os.environ['LC_ALL']); print(os.getcwd())"
    )
    monkeypatch.setattr(commands, "QUERIES", {"fixture": ("python", ("-c", script))})
    monkeypatch.setattr(commands, "resolve_binary", lambda _: Path(sys.executable))
    result = commands.run_query("fixture")
    assert result.state == "done"
    assert result.output.splitlines() == ["absent", "C", "/"]


def test_pipe_inheriting_descendant_is_bounded_and_group_is_killed(monkeypatch):
    import os
    import signal

    if not hasattr(os, "fork"):
        pytest.skip("POSIX process-group behavior")
    script = (
        "import os,time; child=os.fork(); time.sleep(5) if child == 0 else os._exit(0)"
    )
    monkeypatch.setattr(commands, "QUERIES", {"fixture": ("python", ("-c", script))})
    monkeypatch.setattr(commands, "resolve_binary", lambda _: Path(sys.executable))
    original = os.killpg
    signals = []

    def kill_group(pid, value):
        signals.append(value)
        return original(pid, value)

    monkeypatch.setattr(commands.os, "killpg", kill_group)
    result = commands.run_query("fixture", timeout=0.1)
    assert result.state == "error"
    assert result.output == ""
    assert signal.SIGKILL in signals


def test_invalid_query_output_is_not_replaced_into_valid_text(monkeypatch):
    script = "import os; os.write(1, bytes([255]))"
    monkeypatch.setattr(commands, "QUERIES", {"fixture": ("python", ("-c", script))})
    monkeypatch.setattr(commands, "resolve_binary", lambda _: Path(sys.executable))
    result = commands.run_query("fixture")
    assert result.state == "error"
    assert result.output == ""


@pytest.mark.parametrize(
    "name", ["nft; touch sentinel", "$(id)", "--help", "nft\nwhoami"]
)
def test_command_injection_never_reaches_process_creation(monkeypatch, name):
    def forbidden(*args, **kwargs):
        pytest.fail("Unrecognized query reached process creation")

    monkeypatch.setattr(commands.subprocess, "Popen", forbidden)
    assert commands.run_query(name).state == "error"


def test_hostile_path_cannot_supply_query_binary(tmp_path, monkeypatch):
    binary = tmp_path / "nft"
    binary.write_text("#!/bin/sh\nexit 99\n")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    resolved = commands.resolve_binary("nft")
    assert resolved is None or resolved != binary
