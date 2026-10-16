"""Guidance coverage and evidence models enforce data minimization."""

from dataclasses import FrozenInstanceError, asdict

import pytest

from hardcheck.catalog import GUIDANCE
from hardcheck.models import Evidence, EvidenceKey, EvidenceValue, Status
from hardcheck.registry import get_registered_checks


def test_all_checks_have_actionable_guidance_without_running_probes():
    checks = get_registered_checks()
    assert set(GUIDANCE) == {check.check_id for check in checks}
    for check in checks:
        result = check.result(check, Status.SKIP)
        assert (
            result.title and result.expected and result.rationale and result.remediation
        )
        assert result.reference.startswith("https://")
        assert result.evidence == (
            Evidence(EvidenceKey.ASSESSMENT, EvidenceValue.UNKNOWN),
        )


@pytest.mark.parametrize(
    "value", ["private-user", "$secret$hash", "\x1b[31m", {}, True]
)
def test_arbitrary_evidence_is_rejected(value):
    with pytest.raises(ValueError):
        Evidence(EvidenceKey.SETTING, value)


def test_evidence_is_immutable_and_serializable():
    fact = Evidence(EvidenceKey.MATCHES, 2)
    assert asdict(fact)["value"] == 2
    with pytest.raises(FrozenInstanceError):
        fact.value = 3
    with pytest.raises(ValueError):
        Evidence("private-key", 2)


def test_ssh_evidence_never_echoes_invalid_secret(tmp_path):
    from hardcheck.checks.ssh import SshRootLoginDisabledCheck

    path = tmp_path / "sshd_config"
    path.write_text("PermitRootLogin private-secret-token\n")
    result = SshRootLoginDisabledCheck(path).run()
    assert result.status == Status.FAIL
    assert result.evidence == (Evidence(EvidenceKey.SETTING, EvidenceValue.INVALID),)
    assert "private-secret-token" not in repr(result)
    path.write_text("PermitRootLogin no\n")
    assert SshRootLoginDisabledCheck(path).run().evidence[0].value == EvidenceValue.NO


def test_password_policy_evidence_reports_credits(tmp_path):
    from hardcheck.checks.password_policy import PasswordLengthCheck

    path = tmp_path / "pwquality.conf"
    path.write_text("minlen = 12\ndcredit = 1\n")
    result = PasswordLengthCheck(path).run()
    assert result.status == Status.FAIL
    assert dict((e.key, e.value) for e in result.evidence) == {
        EvidenceKey.SETTING: 12,
        EvidenceKey.CREDIT: 1,
        EvidenceKey.ENFORCING: 1,
    }


def test_account_evidence_contains_counts_without_identities(tmp_path):
    from hardcheck.checks.users import EmptyPasswordCheck, RootUidCheck

    shadow = tmp_path / "shadow"
    shadow.write_text("private-user::20000:0:90:7:::\nroot:!:20000:0:90:7:::\n")
    result = EmptyPasswordCheck(shadow).run()
    assert {e.key: e.value for e in result.evidence} == {
        EvidenceKey.RECORDS: 2,
        EvidenceKey.MATCHES: 1,
    }
    assert "private-user" not in repr(result)
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0::/:/bin/sh\nprivate-user:x:0:0::/:/bin/sh\n")
    result = RootUidCheck(passwd).run()
    assert {e.key: e.value for e in result.evidence}[EvidenceKey.MATCHES] == 1
    assert "private-user" not in repr(result)


def test_filesystem_evidence_is_numeric_without_private_paths(tmp_path):
    import os

    from hardcheck.checks.filesystem import ShadowPermissionsCheck
    from hardcheck.checks.world_writable import WorldWritableEtcCheck

    path = tmp_path / "secret-private-filename"
    path.write_text("private-content")
    path.chmod(0o666)
    result = ShadowPermissionsCheck(path, os.getuid()).run()
    assert {e.key: e.value for e in result.evidence}[EvidenceKey.MODE] == 0o666
    assert "secret-private-filename" not in repr(result)
    result = WorldWritableEtcCheck(tmp_path).run()
    assert {e.key: e.value for e in result.evidence}[EvidenceKey.MATCHES] == 1
    assert "secret-private-filename" not in repr(result)
    assert "private-content" not in repr(result)


def test_kernel_evidence_does_not_echo_malformed_values(tmp_path):
    from hardcheck.checks.sysctl import AslrCheck

    path = tmp_path / "kernel/randomize_va_space"
    path.parent.mkdir()
    path.write_text("private-secret-token")
    result = AslrCheck(tmp_path).run()
    assert result.evidence == (Evidence(EvidenceKey.SETTING, EvidenceValue.INVALID),)
    assert "private-secret-token" not in repr(result)
    path.write_text("2")
    assert AslrCheck(tmp_path).run().evidence[0].value == 2


def test_firewall_evidence_never_echoes_raw_output(monkeypatch):
    from hardcheck.checks import firewall
    from hardcheck.commands import CommandResult

    monkeypatch.setattr(
        firewall,
        "run_query",
        lambda query: (
            CommandResult("done", "Status: active\nprivate-secret-token", 0)
            if query == "ufw"
            else CommandResult("missing")
        ),
    )
    result = firewall.FirewallCheck().run()
    assert result.evidence[0].value == EvidenceValue.UFW
    assert "private-secret-token" not in repr(result)


def test_explain_output_keeps_exit_status_and_no_raw_data(
    tmp_path, monkeypatch, capsys
):
    from hardcheck import cli
    from hardcheck.checks.filesystem import ShadowPermissionsCheck

    path = tmp_path / "private-file-name"
    path.write_text("private-content")
    path.chmod(0o666)
    result = ShadowPermissionsCheck(path).run()
    monkeypatch.setattr(cli, "run_checks", lambda policy: [result])
    assert cli.main(["scan", "--explain"]) == 1
    output = capsys.readouterr().out
    for label in (
        "Expected:",
        "Observed:",
        "Rationale:",
        "Manual remediation:",
        "Reference:",
    ):
        assert label in output
    assert "mode_bits=0666" in output
    assert "private-file-name" not in output
    assert "private-content" not in output
    assert cli.main(["scan"]) == 1
    assert len(capsys.readouterr().out.splitlines()) == 3


def test_error_and_skip_never_invent_evidence():
    check = get_registered_checks()[0]
    for status in (Status.ERROR, Status.SKIP, Status.WARN):
        result = check.result(check, status)
        assert result.evidence[0].value == EvidenceValue.UNKNOWN
        assert result.remediation
