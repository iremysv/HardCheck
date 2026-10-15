"""Base interface for read-only security checks."""

from abc import ABC, abstractmethod

from hardcheck.models import CheckResult, Severity, Status


class BaseCheck(ABC):
    """Describe the required metadata and behavior of a check."""

    check_id: str
    category: str
    severity: Severity
    reference: str

    def result(self, status: Status, detail: str = "") -> CheckResult:
        """Create a consistent result with localization keys."""
        prefix = f"checks.{self.check_id}"
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
        )

    @abstractmethod
    def run(self) -> CheckResult:
        """Inspect system configuration without changing it."""
        raise NotImplementedError
