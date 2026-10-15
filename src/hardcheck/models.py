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


class EvidenceKey(StrEnum):
    ASSESSMENT = "assessment"
    SETTING = "setting"
    RECORDS = "records_inspected"
    MATCHES = "noncompliant_records"
    OWNER_UID = "owner_uid"
    MODE = "mode_bits"
    STICKY = "sticky_bit"
    COVERAGE = "coverage"
    FILES = "entries_inspected"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    PORT21 = "tcp_21_listeners"
    PORT23 = "tcp_23_listeners"
    BACKEND = "backend"
    PACKAGE = "legacy_package"
    UNIT = "legacy_unit"
    CREDIT = "positive_credits"
    ENFORCING = "enforcing"


class EvidenceValue(StrEnum):
    UNKNOWN = "unknown"
    NO = "no"
    YES = "yes"
    INVALID = "invalid"
    COMPLETE = "complete_within_scope"
    PARTIAL = "partial"
    PRESENT = "present"
    ABSENT = "absent"
    UFW = "ufw"
    NFT = "nft"
    IPTABLES = "iptables"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Only fixed enum tokens and bounded integers may enter public evidence."""

    key: EvidenceKey
    value: EvidenceValue | int

    def __post_init__(self) -> None:
        if not isinstance(self.key, EvidenceKey):
            raise ValueError("Evidence key must be allowlisted")
        if isinstance(self.value, EvidenceValue):
            return
        if type(self.value) is not int or not -(2**32) <= self.value < 2**64:
            raise ValueError("Evidence must be a safe token or bounded integer")


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

    title: str = ""
    expected: str = ""
    rationale: str = ""
    remediation: str = ""
    evidence: tuple[Evidence, ...] = ()
