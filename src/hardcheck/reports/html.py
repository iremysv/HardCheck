"""Offline HTML with automatic escaping and no active content or remote assets."""

import base64
import hashlib
from collections.abc import Sequence
from importlib.resources import files
from urllib.parse import urlsplit

from jinja2 import Environment, PackageLoader, StrictUndefined

from hardcheck.localization import catalog, detail_text, evidence_text, translate
from hardcheck.models import CheckResult
from hardcheck.reporting import report_data


def reference_url(value: str) -> str | None:
    """Only permit explicit HTTPS references without credentials or control chars."""
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
        ):
            return value
    except ValueError:
        pass
    return None


def html_report(
    results: Sequence[CheckResult],
    all_results: Sequence[CheckResult],
    minimum_severity: str | None = None,
    language: str = "en",
) -> str:
    """Render the same scores and safe evidence as JSON in a bundled template."""
    report = report_data(results, all_results, minimum_severity, language)
    for finding, result in zip(report["findings"], results, strict=True):
        finding["status_label"] = translate("status." + result.status.value, language)
        finding["severity_label"] = translate(
            "severity." + result.severity.value, language
        )
        finding["category_label"] = catalog(language).get(
            "category." + result.category, result.category
        )
        finding["evidence_labels"] = [
            evidence_text(fact, language) for fact in result.evidence
        ]
        finding["note"] = detail_text(result, language)
        finding["reference_url"] = reference_url(result.reference)
    stylesheet = (
        files("hardcheck.reports")
        .joinpath("templates/report.css")
        .read_text(encoding="utf-8")
    )
    style_hash = base64.b64encode(hashlib.sha256(stylesheet.encode()).digest()).decode()
    environment = Environment(
        loader=PackageLoader("hardcheck", "reports/templates"),
        autoescape=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )

    def percent(value):
        return translate("na", language) if value is None else f"{value}%"

    return environment.get_template("report.html.j2").render(
        report=report,
        labels=catalog(language),
        stylesheet=stylesheet,
        style_hash=style_hash,
        score=percent(report["summary"]["score_percent"]),
        coverage=percent(report["summary"]["coverage_percent"]),
        filter_label=translate("severity." + minimum_severity, language)
        if minimum_severity
        else translate("all", language),
    )
