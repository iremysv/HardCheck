"""Base interface for read-only security checks."""

from abc import ABC, abstractmethod

from hardcheck.catalog import GUIDANCE
from hardcheck.models import (
    CheckResult,
    Evidence,
    EvidenceKey,
    EvidenceValue,
    Severity,
    Status,
)


class BaseCheck(ABC):
    """Describe the required metadata and behavior of a check."""

    check_id: str
    category: str
    severity: Severity
    reference: str

    def result(
        self,
        status: Status,
        detail: str = "",
        *,
        evidence: tuple[Evidence, ...] = (),
    ) -> CheckResult:
        """Create a consistent result with localization keys."""
        prefix = f"checks.{self.check_id}"
        guidance = GUIDANCE.get(self.check_id)
        return CheckResult(
            check_id=self.check_id,
            title_key=f"{prefix}.title",
            category=self.category,
            severity=self.severity,
            status=status,
            description_key=f"{prefix}.description",
            remediation_key=f"{prefix}.remediation",
            reference=self.reference,
            detail=detail,
            title=guidance.title if guidance else self.check_id,
            expected=guidance.expected if guidance else "Not specified",
            rationale=guidance.rationale if guidance else "Not specified",
            remediation=guidance.remediation if guidance else "Manual review required",
            evidence=evidence
            or (Evidence(EvidenceKey.ASSESSMENT, EvidenceValue.UNKNOWN),),
        )

    @abstractmethod
    def run(self) -> CheckResult:
        """Inspect system configuration without changing it."""
        raise NotImplementedError
