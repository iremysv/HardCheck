"""Render a versioned report with explicit scope and sanitized evidence."""

import json
from collections.abc import Sequence
from dataclasses import asdict

from hardcheck import __version__
from hardcheck.environment import public_environment
from hardcheck.localization import (
    detail_text,
    evidence_text,
    localize_result,
    translate,
)
from hardcheck.models import CheckResult, Status
from hardcheck.scoring import summarize


def report_data(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    minimum_severity: str | None = None,
    language: str = "en",
) -> dict:
    """Build the shared public contract without raw detail or command output."""
    translate("title", language)
    findings = []
    for original in results:
        result = localize_result(original, language)
        findings.append(
            {
                "check_id": result.check_id,
                "title": result.title,
                "category": result.category,
                "severity": result.severity.value,
                "status": result.status.value,
                "reason": result.reason.value,
                "note": detail_text(result, language),
                "environment": public_environment(result.environment),
                "expected": result.expected,
                "rationale": result.rationale,
                "remediation": result.remediation,
                "reference": result.reference,
                "evidence": [asdict(fact) for fact in result.evidence],
            }
        )
    environments = []
    for result in all_results:
        environment = public_environment(result.environment)
        if environment is not None and environment not in environments:
            environments.append(environment)
    return {
        "schema_version": 1,
        "language": language,
        "hardcheck_version": __version__,
        "scope": {
            "basis": "displayed_controls",
            "min_severity": minimum_severity,
            "collected_controls": len(all_results),
            "hidden_controls": len(all_results) - len(results),
            "host_namespace_verified": False,
            "environments": environments,
            "limitations": translate("limitations", language),
        },
        "summary": asdict(summarize(results)),
        "scan_summary": asdict(summarize(all_results)),
        "findings": findings,
    }


def json_report(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    minimum_severity: str | None = None,
    language: str = "en",
) -> str:
    """Serialize the shared report contract as one JSON document."""
    return (
        json.dumps(
            report_data(results, all_results, minimum_severity, language),
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    )


def terminal_summary(results: Sequence[CheckResult], language: str = "en") -> str:
    """Always show coverage alongside the conditional compliance score."""
    summary = summarize(results)
    score = (
        translate("na", language)
        if summary.score_percent is None
        else f"{summary.score_percent}%"
    )
    coverage = (
        translate("na", language)
        if summary.coverage_percent is None
        else f"{summary.coverage_percent}%"
    )
    counts = " ".join(f"{key}={value}" for key, value in summary.counts.items())
    return (
        f"{translate('summary', language)}: {counts}\n"
        f"{translate('score', language)}: {score}; "
        f"{translate('assessed', language)}: {summary.assessed}/{summary.total} "
        f"({coverage}); {translate('scope', language)}: "
        f"{translate('displayed_controls', language)}; "
        f"{translate('namespace', language)}"
    )


def terminal_report(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    explain: bool = False,
    language: str = "en",
) -> str:
    """Render localized findings without mutating scan results."""
    lines = []
    for original in results:
        result = localize_result(original, language)
        detail = detail_text(result, language)
        suffix = f" — {detail}" if detail else ""
        lines.append(f"{result.check_id}: {result.status.value}{suffix}")
        if explain:
            for field in (
                "title",
                "expected",
                "observed",
                "rationale",
                "remediation",
                "reference",
            ):
                value = (
                    "; ".join(evidence_text(fact, language) for fact in result.evidence)
                    if field == "observed"
                    else getattr(result, field)
                )
                lines.append(f"  {translate(field, language)}: {value}")
    lines.append(terminal_summary(results, language))
    if len(results) != len(all_results):
        errors = sum(result.status == Status.ERROR for result in all_results)
        lines.append(
            f"{translate('hidden', language)}: "
            f"{len(all_results) - len(results)}; "
            f"{translate('scan_errors', language)}={errors}"
        )
    return "\n".join(lines) + "\n"
