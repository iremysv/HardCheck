"""Tests for the scan engine."""

from hardcheck.checks import ssh
from hardcheck.engine import run_checks
from hardcheck.models import Status


def test_engine_collects_four_ssh_results(monkeypatch, tmp_path):
    """Run all checks against a temporary SSH fixture."""
    config = tmp_path / "sshd_config"
    config.write_text(
        "PermitRootLogin no\nPasswordAuthentication no\n"
        "MaxAuthTries 4\nPermitEmptyPasswords no\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ssh.SshSettingCheck,
        "__init__",
        lambda self: setattr(self, "config_path", config),
    )
    results = run_checks()
    assert len(results) == 4
    assert all(result.status == Status.PASS for result in results)
