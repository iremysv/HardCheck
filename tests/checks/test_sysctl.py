"""Live value controls use fake proc roots, not sysctl commands."""

import pytest

from hardcheck.checks.sysctl import AslrCheck, DmesgRestrictCheck, IpForwardingCheck
from hardcheck.models import Status


@pytest.mark.parametrize("check", [AslrCheck, DmesgRestrictCheck, IpForwardingCheck])
def test_sysctl_outcomes(tmp_path, check):
    assert check(tmp_path).run().status == Status.SKIP
    for source in check.sources:
        path = tmp_path / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(check.expected + "\n")
    assert check(tmp_path).run().status == Status.PASS
    path.write_text("1" if check.expected != "1" else "0")
    assert check(tmp_path).run().status == Status.FAIL
    path.write_text("not-an-integer")
    assert check(tmp_path).run().status == Status.WARN


def test_forwarding_partial_evidence(tmp_path):
    path = tmp_path / "net/ipv4/ip_forward"
    path.parent.mkdir(parents=True)
    path.write_text("0")
    assert IpForwardingCheck(tmp_path).run().status == Status.SKIP
    path.write_text("1")
    assert IpForwardingCheck(tmp_path).run().status == Status.FAIL
