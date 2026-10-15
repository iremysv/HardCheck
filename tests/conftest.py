"""Engine tests use a known environment instead of probing the host by default."""

import pytest

from hardcheck.environment import Environment


@pytest.fixture(autouse=True)
def known_engine_environment(monkeypatch):
    monkeypatch.setattr(
        "hardcheck.engine.detect_environment",
        lambda: Environment("Linux", "fixture", "systemd", None),
    )
