"""Render a versioned report with explicit scope and sanitized evidence."""

import json
from collections.abc import Sequence
from dataclasses import asdict

from hardcheck import __version__
from hardcheck.models import CheckResult
from hardcheck.scoring import summarize


def report_data(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    minimum_severity: str | None = None,
) -> dict:
    """Build the shared public contract without raw detail or command output."""
    findings = []
    for result in results:
        findings.append(
            {
                "check_id": result.check_id,
                "title": result.title,
                "category": result.category,
                "severity": result.severity.value,
                "status": result.status.value,
                "expected": result.expected,
                "rationale": result.rationale,
                "remediation": result.remediation,
                "reference": result.reference,
                "evidence": [asdict(fact) for fact in result.evidence],
            }
        )
    return {
        "schema_version": 1,
        "hardcheck_version": __version__,
        "scope": {
            "basis": "displayed_controls",
            "min_severity": minimum_severity,
            "collected_controls": len(all_results),
            "hidden_controls": len(all_results) - len(results),
            "host_namespace_verified": False,
            "limitations": "Bounded observations; not a security guarantee.",
        },
        "summary": asdict(summarize(results)),
        "scan_summary": asdict(summarize(all_results)),
        "findings": findings,
    }


def json_report(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    minimum_severity: str | None = None,
) -> str:
    """Serialize the shared report contract as one JSON document."""
    return (
        json.dumps(
            report_data(results, all_results, minimum_severity),
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    )


def terminal_summary(results: Sequence[CheckResult]) -> str:
    """Always show coverage alongside the conditional compliance score."""
    summary = summarize(results)
    score = "N/A" if summary.score_percent is None else f"{summary.score_percent}%"
    coverage = (
        "N/A" if summary.coverage_percent is None else f"{summary.coverage_percent}%"
    )
    counts = " ".join(f"{key}={value}" for key, value in summary.counts.items())
    return (
        f"Summary: {counts}\n"
        f"Score: {score}; assessed: {summary.assessed}/{summary.total} "
        f"({coverage}); scope: displayed controls; host namespace unverified"
    )
