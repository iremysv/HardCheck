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
