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
    def fixture_init(self):
        self.config_path = config
        self.include_root = tmp_path

    monkeypatch.setattr(ssh.SshSettingCheck, "__init__", fixture_init)
    results = run_checks()
    assert len(results) == 4
    assert all(result.status == Status.PASS for result in results)


def test_check_error_does_not_stop_other_checks(monkeypatch):
    """Exceptions become ERROR without exposing exception text."""
    def broken(self):
        raise RuntimeError("sensitive fixture data")

    monkeypatch.setattr(ssh.SshSettingCheck, "run", broken)
    results = run_checks()
    assert len(results) == 4
    assert all(result.status == Status.ERROR for result in results)
    assert all("sensitive" not in result.detail for result in results)


def test_constructor_error_is_isolated(monkeypatch):
    """A failed constructor cannot abort the entire audit."""
    def broken(self):
        raise PermissionError("private fixture path")

    monkeypatch.setattr(ssh.SshSettingCheck, "__init__", broken)
    results = run_checks()
    assert len(results) == 4
    assert all(result.status == Status.ERROR for result in results)
    assert all("private" not in result.detail for result in results)
