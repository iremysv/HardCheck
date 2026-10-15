"""Immutable models for security check metadata and results."""

from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    """Possible security check outcomes."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(StrEnum):
    """Supported security risk priorities."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result metadata with keys for later localization."""

    check_id: str
    title_key: str
    category: str
    severity: Severity
    status: Status
    description_key: str
    remediation_key: str
    reference: str
    detail: str = ""
