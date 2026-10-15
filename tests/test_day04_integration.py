"""Full scan integration without reading real proc tables or running system tools."""

from hardcheck import engine
from hardcheck.checks.base import BaseCheck
from hardcheck.cli import main
from hardcheck.config import load_policy
from hardcheck.environment import Environment
from hardcheck.models import Status
from hardcheck.registry import get_registered_checks


def test_all_eighteen_registered_and_policy_aware(tmp_path, monkeypatch):
    checks = get_registered_checks()
    assert len(checks) == 18
    assert len({c.check_id for c in checks}) == 18
    for check in checks:
        monkeypatch.setattr(check, "__init__", lambda self: None)
        monkeypatch.setattr(check, "run", lambda self: self.result(Status.PASS))
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nchecks:\n  NET-001: {enabled: false}\n"
        "  KRN-001: {severity: critical}\n  SVC-001: {enabled: false}\n"
    )
    results = {r.check_id: r for r in engine.run_checks(load_policy(path))}
    assert len(results) == 18
    assert results["NET-001"].status == Status.SKIP
    assert results["SVC-001"].status == Status.SKIP
    assert results["KRN-001"].severity.value == "critical"
    assert all("host namespace unverified" in r.detail for r in results.values())


def test_non_linux_does_not_construct_or_execute_checks(monkeypatch):
    def forbidden(self):
        raise AssertionError("Unsupported environment must not run probes")

    for check in get_registered_checks():
        monkeypatch.setattr(check, "__init__", forbidden)
    results = engine.run_checks(environment=Environment("Darwin"))
    assert len(results) == 18
    assert all(r.status == Status.SKIP for r in results)


def test_container_scope_remains_explicit(monkeypatch):
    class FakeCheck(BaseCheck):
        check_id = "KRN-001"
        category = "kernel"
        severity = get_registered_checks()[0].severity
        reference = "fixture"

        def run(self):
            return self.result(Status.WARN)

    monkeypatch.setattr(engine, "get_registered_checks", lambda: (FakeCheck,))
    results = engine.run_checks(environment=Environment("Linux", container=True))
    assert "container=detected" in results[0].detail
    assert "host namespace unverified" in results[0].detail


def test_cli_lists_eighteen_without_probes(capsys):
    assert main(["list-checks"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 18
    assert lines == sorted(lines)
