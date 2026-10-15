"""Run registered security checks independently."""

from dataclasses import replace

from hardcheck.checks import ssh as ssh_checks  # noqa: F401
from hardcheck.config import Policy, Rule
from hardcheck.models import CheckResult, Status
from hardcheck.registry import get_registered_checks


def run_checks(policy: Policy | None = None) -> list[CheckResult]:
    """Collect results without allowing one check to crash the scan."""
    results: list[CheckResult] = []
    for check_class in get_registered_checks():
        rule = policy.rules.get(check_class.check_id, Rule()) if policy else Rule()
        check = check_class()
        if not rule.enabled:
            results.append(check.result(Status.SKIP, "Disabled by scan policy"))
            continue
        try:
            results.append(check.run())
        except Exception:
            results.append(check.result(Status.ERROR))
        if rule.severity is not None:
            results[-1] = replace(results[-1], severity=rule.severity)
    return results
