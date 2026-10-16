"""Transparent equal-weight scoring of conclusive observations only."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from hardcheck.models import CheckResult, Status


@dataclass(frozen=True, slots=True)
class Summary:
    """Coverage and score describe the selected controls, not host security."""

    total: int
    counts: dict[str, int]
    assessed: int
    coverage_percent: float | None
    score_percent: float | None


def summarize(results: Sequence[CheckResult]) -> Summary:
    """PASS earns one point; FAIL earns zero; uncertain results are unscored."""
    counts = Counter(result.status for result in results)
    assessed = counts[Status.PASS] + counts[Status.FAIL]
    return Summary(
        total=len(results),
        counts={status.value: counts[status] for status in Status},
        assessed=assessed,
        coverage_percent=round(100 * assessed / len(results), 2) if results else None,
        score_percent=round(100 * counts[Status.PASS] / assessed, 2)
        if assessed
        else None,
    )


def exit_code(results: Sequence[CheckResult]) -> int:
    """Operational errors take precedence over noncompliance."""
    if any(result.status == Status.ERROR for result in results):
        return 2
    return 1 if any(result.status == Status.FAIL for result in results) else 0
