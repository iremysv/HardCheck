"""Adversarial policy tests without accessing host configuration."""

import pytest

from hardcheck.cli import main
from hardcheck.config import ConfigError, load_policy
from hardcheck.engine import run_checks
from hardcheck.models import Severity, Status


@pytest.mark.parametrize("content", [
    "!!python/object/apply:os.system ['touch /tmp/hardcheck-no']",
    "version: 1\nversion: 1\nchecks: {}",
    "version: true\nchecks: {}",
    "version: 2\nchecks: {}",
    "version: 1\nchecks: []",
    "version: 1\nchecks: {SSH-099: {}}",
    "version: 1\nchecks: {SSH-001: {enabled: 1}}",
    "version: 1\nchecks: {SSH-001: {severity: urgent}}",
    "version: 1\nchecks: {SSH-001: {command: whoami}}",
    "version: 1\nchecks: {SSH-001: {}, SSH-001: {}}",
    "version: 1\nchecks: &a {SSH-001: *a}",
    "version: 1\nchecks: {}\nextra: true",
    "version: 1\nchecks: {SSH-001: {severity: [high]}}",
    "version: 1\nchecks: {SSH-001: {severity: null}}",
    "[",
    "",
    "a: " + "[" * 30 + "0" + "]" * 30,
    "#" * 65537,
])
def test_invalid_policy_is_rejected(tmp_path, content):
    path = tmp_path / "policy.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError):
        load_policy(path)


def test_policy_controls_existing_checks(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nchecks: {SSH-001: {enabled: false}}")
    policy = load_policy(path)
    from hardcheck.checks.ssh import SshRootLoginDisabledCheck

    def forbidden(self):
        raise AssertionError("Disabled checks must never run")

    monkeypatch.setattr(SshRootLoginDisabledCheck, "run", forbidden)
    # Disable all remaining checks to avoid any host reads in this test.
    path.write_text("version: 1\nchecks:\n" + "".join(
        f"  SSH-00{i}: {{enabled: false}}\n" for i in range(1, 5)
    ))
    results = run_checks(load_policy(path))
    assert len(results) == 4
    assert all(result.status == Status.SKIP for result in results)
    with pytest.raises(TypeError):
        policy.rules["SSH-001"] = None


def test_severity_override(tmp_path, monkeypatch):
    from hardcheck.checks.ssh import SshSettingCheck

    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nchecks: {SSH-001: {severity: critical}}")
    monkeypatch.setattr(SshSettingCheck, "run", lambda self: self.result(Status.WARN))
    results = run_checks(load_policy(path))
    assert results[0].severity == Severity.CRITICAL
    assert results[1].severity == Severity.HIGH


def test_cli_rejects_bad_policy_before_scanning(tmp_path, capsys, monkeypatch):
    import hardcheck.cli as cli

    def forbidden(*args):
        raise AssertionError("Invalid policies must prevent scans")

    monkeypatch.setattr(cli, "run_checks", forbidden)
    assert main(["scan", "--config", str(tmp_path / "missing")]) == 2
    assert "Invalid configuration" in capsys.readouterr().err


def test_cli_applies_policy_and_reports_engine_errors(tmp_path, monkeypatch, capsys):
    import hardcheck.cli as cli
    from hardcheck.checks.ssh import SshRootLoginDisabledCheck

    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nchecks: {SSH-001: {severity: critical}}")
    seen = []

    def scan(policy):
        seen.append(policy)
        return [SshRootLoginDisabledCheck().result(Status.ERROR)]

    monkeypatch.setattr(cli, "run_checks", scan)
    assert main(["scan", "--config", str(path)]) == 2
    assert seen[0].rules["SSH-001"].severity == Severity.CRITICAL
    assert "SSH-001: ERROR" in capsys.readouterr().out
    assert main(["scan", "--min-severity", "critical"]) == 0
    assert not capsys.readouterr().out
