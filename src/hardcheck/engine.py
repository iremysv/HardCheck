"""Run registered security checks independently."""

from dataclasses import replace

from hardcheck.checks.base import BaseCheck
from hardcheck.config import Policy, Rule
from hardcheck.environment import Environment, detect_environment
from hardcheck.models import CheckResult, Status
from hardcheck.registry import get_registered_checks


def run_checks(
    policy: Policy | None = None, environment: Environment | None = None
) -> list[CheckResult]:
    """Collect results without allowing one check to crash the scan."""
    environment = environment if environment is not None else detect_environment()
    results: list[CheckResult] = []
    for check_class in get_registered_checks():
        rule = policy.rules.get(check_class.check_id, Rule()) if policy else Rule()
        if environment.system != "Linux":
            result = BaseCheck.result(
                check_class, Status.SKIP, "This check requires Linux"
            )
        elif not rule.enabled:
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
        container = "detected" if environment.container else "unknown"
        scope = (
            f"Scope: Linux={environment.system == 'Linux'}, "
            f"distribution={environment.distribution}, "
            f"init={environment.service_manager}, container={container}; "
            "host namespace unverified"
        )
        result = replace(result, detail=f"{result.detail}; {scope}".lstrip("; "))
        results.append(result)
    return results
