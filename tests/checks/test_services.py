"""Service tests use fixed command responses only."""

import pytest

from hardcheck.checks import services
from hardcheck.commands import CommandResult
from hardcheck.models import Status


def responses(name):
    values = {
        "packages-deb": CommandResult("done", "base-files\tinstalled\n", 0),
        "packages-rpm": CommandResult("missing"),
        "unit-files": CommandResult("done", "ssh.service enabled\n", 0),
        "units": CommandResult("done", "ssh.service loaded active running\n", 0),
    }
    return values[name]


def test_absent_legacy_services(monkeypatch):
    monkeypatch.setattr(services, "run_query", responses)
    assert services.LegacyServiceCheck().run().status == Status.PASS


@pytest.mark.parametrize(
    ("query", "output"),
    [
        ("packages-deb", "telnet:amd64\tinstalled\n"),
        ("packages-rpm", "rsh-server\n"),
        ("unit-files", "telnet@.service disabled\n"),
        ("units", "rsh.socket loaded active listening\n"),
    ],
)
def test_legacy_evidence(monkeypatch, query, output):
    monkeypatch.setattr(
        services,
        "run_query",
        lambda name: (
            CommandResult("done", output, 0) if name == query else responses(name)
        ),
    )
    result = services.LegacyServiceCheck().run()
    assert result.status == Status.FAIL
    assert "amd64" not in result.detail


def test_incomplete_observation_never_passes(monkeypatch):
    monkeypatch.setattr(services, "run_query", lambda name: CommandResult("missing"))
    assert services.LegacyServiceCheck().run().status == Status.SKIP
    monkeypatch.setattr(
        services,
        "run_query",
        lambda name: (
            CommandResult("done", "", 1) if name == "units" else responses(name)
        ),
    )
    assert services.LegacyServiceCheck().run().status == Status.WARN
    monkeypatch.setattr(
        services, "run_query", lambda name: CommandResult("done", "?", 0)
    )
    assert services.LegacyServiceCheck().run().status == Status.WARN
