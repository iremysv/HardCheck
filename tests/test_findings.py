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
