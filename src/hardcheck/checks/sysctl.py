"""Live sysctl reads in the current namespace, without changing kernel settings."""

from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import CheckResult, Severity, Status
from hardcheck.safe_io import read_regular_text


class SysctlCheck(BaseCheck):
    category = "kernel"
    severity = Severity.HIGH
    reference = "https://docs.kernel.org/admin-guide/sysctl/kernel.html"
    sources: tuple[str, ...]
    expected: str

    def __init__(self, root: Path = Path("/proc/sys")) -> None:
        self.root = root

    def run(self) -> CheckResult:
        unavailable = False
        malformed = False
        failed = False
        for source in self.sources:
            try:
                value = read_regular_text(self.root / source, 64).strip()
                if value not in {"0", "1", "2"}:
                    malformed = True
                elif value != self.expected:
                    failed = True
            except (OSError, UnicodeError, ValueError):
                unavailable = True
        status = (
            Status.FAIL if failed else Status.WARN if malformed
            else Status.SKIP if unavailable else Status.PASS
        )
        return self.result(
            status, "Live namespace values; persistence and host scope unverified"
        )


class AslrCheck(SysctlCheck):
    check_id = "KRN-001"
    sources = ("kernel/randomize_va_space",)
    expected = "2"


class DmesgRestrictCheck(SysctlCheck):
    check_id = "KRN-002"
    sources = ("kernel/dmesg_restrict",)
    expected = "1"


class IpForwardingCheck(SysctlCheck):
    check_id = "NET-003"
    category = "network"
    reference = "https://docs.kernel.org/networking/ip-sysctl.html"
    sources = ("net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding")
    expected = "0"
