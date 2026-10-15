"""Run registered security checks independently."""

from hardcheck.checks import ssh as ssh_checks  # noqa: F401
from hardcheck.models import CheckResult, Status
from hardcheck.registry import get_registered_checks


def run_checks() -> list[CheckResult]:
    """Collect results without allowing one check to crash the scan."""
    results: list[CheckResult] = []
    for check_class in get_registered_checks():
        check = check_class()
        try:
            results.append(check.run())
        except Exception:
            results.append(check.result(Status.ERROR))
    return results
