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
