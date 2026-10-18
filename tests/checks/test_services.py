"""Service tests use fixed command responses only."""

import pytest

from hardcheck.checks import services
from hardcheck.commands import CommandResult
from hardcheck.models import EvidenceKey, EvidenceValue, Status


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


@pytest.mark.parametrize("query,valid,malformed", [
    ("packages-deb", "telnet\tinstalled\n", "malformed\n"),
    ("packages-deb", "telnet\tinstalled\n", "base-files\tunknown-state\n"),
    ("packages-rpm", "rsh-server\n", "invalid package name\n"),
    ("unit-files", "telnet@.service disabled\n", "malformed\n"),
    ("units", "rsh.socket loaded active listening\n", "malformed\n"),
])
@pytest.mark.parametrize("bad_first", [True, False])
def test_malformed_record_does_not_hide_legacy_evidence(
    monkeypatch, query, valid, malformed, bad_first
):
    output = malformed + valid if bad_first else valid + malformed
    monkeypatch.setattr(
        services, "run_query",
        lambda name: CommandResult("done", output, 0)
        if name == query else responses(name),
    )
    assert services.LegacyServiceCheck().run().status == Status.FAIL


@pytest.mark.parametrize("query,output", [
    ("packages-deb", "malformed\nbase-files\tinstalled\n"),
    ("packages-rpm", "invalid package name\nbase-files\n"),
    ("unit-files", "malformed\nssh.service enabled\n"),
    ("units", "malformed\nssh.service loaded active running\n"),
])
def test_malformed_inventory_with_only_safe_records_stays_uncertain(
    monkeypatch, query, output
):
    monkeypatch.setattr(
        services, "run_query",
        lambda name: CommandResult("done", output, 0)
        if name == query else responses(name),
    )
    result = services.LegacyServiceCheck().run()
    assert result.status == Status.WARN
    facts = {fact.key: fact.value for fact in result.evidence}
    assert facts[EvidenceKey.COVERAGE] == EvidenceValue.PARTIAL


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
