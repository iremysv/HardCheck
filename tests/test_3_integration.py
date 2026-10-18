"""All twelve controls integrated with YAML, engine and CLI using fake systems."""

import os

import pytest

from hardcheck.cli import main
from hardcheck.config import load_policy
from hardcheck.engine import run_checks
from hardcheck.models import Status
from hardcheck.registry import get_registered_checks


@pytest.fixture
def fake_system(tmp_path, monkeypatch):
    fixtures = {
        # Synthetic account record; x is a placeholder, not a password.
        "passwd": "root:x:0:0::/root:/bin/sh\n",  # pragma: allowlist secret
        "shadow": "root:!:20000:0:90:7:::\n",
        "login.defs": "PASS_MAX_DAYS 90\n",
        "pwquality.conf": "minlen = 12\n",
        "sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n"
        "MaxAuthTries 4\nPermitEmptyPasswords no\n",
    }
    for name, content in fixtures.items():
        (tmp_path / name).write_text(content)
    (tmp_path / "passwd").chmod(0o644)
    (tmp_path / "shadow").chmod(0o640)
    (tmp_path / "tmp").mkdir()
    (tmp_path / "tmp").chmod(0o1777)
    (tmp_path / "etc").mkdir()
    targets = {
        "USR-001": "shadow",
        "USR-002": "passwd",
        "USR-003": "login.defs",
        "USR-004": "pwquality.conf",
        "FS-001": "passwd",
        "FS-002": "shadow",
        "FS-003": "tmp",
        "FS-004": "etc",
    }
    import hardcheck.engine as engine

    checks = tuple(
        c
        for c in get_registered_checks()
        if c.check_id.startswith(("FS-", "USR-", "SSH-"))
    )
    monkeypatch.setattr(engine, "get_registered_checks", lambda: checks)
    for check in checks:
        if check.check_id.startswith("SSH-"):

            def init(self):
                self.config_path = tmp_path / "sshd_config"
                self.include_root = tmp_path
        elif check.check_id == "FS-004":
            original = check.__init__

            def init(self, original=original):
                original(self, tmp_path / "etc")
        else:
            target = tmp_path / targets[check.check_id]

            def init(self, target=target):
                self.path = target
                self.expected_uid = os.getuid()

        monkeypatch.setattr(check, "__init__", init)
    return tmp_path


def test_all_twelve_checks_pass_on_fake_system(fake_system):
    results = run_checks()
    assert len(results) == 12
    assert len({r.check_id for r in results}) == 12
    assert all(r.status == Status.PASS for r in results)
    assert all(
        r.title and r.expected and r.rationale and r.remediation for r in results
    )
    assert all(r.evidence for r in results)
    assert [r.check_id for r in results] == sorted(r.check_id for r in results)


def test_yaml_controls_new_check_families(fake_system):
    path = fake_system / "policy.yaml"
    path.write_text(
        "version: 1\nchecks:\n  USR-001: {enabled: false}\n"
        "  FS-004: {severity: critical}\n"
    )
    results = {r.check_id: r for r in run_checks(load_policy(path))}
    assert results["USR-001"].status == Status.SKIP
    assert results["FS-004"].severity.value == "critical"


def test_cli_full_scan_uses_all_twelve_checks(fake_system, capsys):
    assert main(["scan"]) == 0
    output = capsys.readouterr().out
    assert len(output.splitlines()) == 14
    assert "USR-004: PASS" in output
    assert "FS-004: PASS" in output
    (fake_system / "shadow").write_text("root::20000:0:90:7:::\n")
    assert main(["scan"]) == 1


def test_registration_is_idempotent_without_scanning(capsys):
    before = get_registered_checks()
    assert main(["list-checks"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 18
    assert before == get_registered_checks()
