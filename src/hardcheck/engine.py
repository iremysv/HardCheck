"""Run registered security checks independently."""

from dataclasses import replace

from hardcheck.checks.base import BaseCheck
from hardcheck.config import Policy, Rule
from hardcheck.models import CheckResult, Status
from hardcheck.registry import get_registered_checks


def run_checks(policy: Policy | None = None) -> list[CheckResult]:
    """Collect results without allowing one check to crash the scan."""
    results: list[CheckResult] = []
    for check_class in get_registered_checks():
        rule = policy.rules.get(check_class.check_id, Rule()) if policy else Rule()
        if not rule.enabled:
            result = BaseCheck.result(
                check_class, Status.SKIP, "Disabled by scan policy"
            )
        else:
            try:
                result = check_class().run()
            except Exception:
                result = BaseCheck.result(
                    check_class, Status.ERROR, "Check could not be completed"
                )
        if rule.severity is not None:
            result = replace(result, severity=rule.severity)
        results.append(result)
    return results
