"""Score uncertainty, empty selections and exit precedence explicitly."""

from dataclasses import replace

import pytest

from hardcheck.models import Status
from hardcheck.registry import get_registered_checks
from hardcheck.scoring import exit_code, summarize


def results(*statuses):
    check = get_registered_checks()[0]
    return [
        replace(check.result(check, status), check_id=f"TEST-{i}")
        for i, status in enumerate(statuses)
    ]


def test_mixed_score_and_coverage():
    summary = summarize(results(*Status))
    assert summary.total == 5
    assert summary.assessed == 2
    assert summary.score_percent == 50
    assert summary.coverage_percent == 40
    assert all(count == 1 for count in summary.counts.values())


@pytest.mark.parametrize("statuses", [(), (Status.SKIP,), (Status.WARN, Status.ERROR)])
def test_uncertainty_has_no_score(statuses):
    summary = summarize(results(*statuses))
    assert summary.score_percent is None
    assert summary.coverage_percent == (0 if statuses else None)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ((), 0),
        ((Status.WARN, Status.SKIP), 0),
        ((Status.PASS,), 0),
        ((Status.FAIL,), 1),
        ((Status.FAIL, Status.ERROR), 2),
    ],
)
def test_exit_precedence(statuses, expected):
    assert exit_code(results(*statuses)) == expected
