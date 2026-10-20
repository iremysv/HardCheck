"""Inspect TCP listeners from both proc tables in the current network namespace."""

import re
from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import (
    CheckResult,
    Evidence,
    EvidenceKey,
    EvidenceValue,
    Severity,
    Status,
)
from hardcheck.safe_io import read_regular_text


class LegacyListenerCheck(BaseCheck):
    check_id = "NET-002"
    category = "network"
    severity = Severity.HIGH
    reference = "https://docs.kernel.org/networking/proc_net_tcp.html"

    def __init__(self, root: Path = Path("/proc/net")) -> None:
        self.root = root

    def run(self) -> CheckResult:
        failed = False
        unavailable = False
        malformed = False
        observed_table = False
        counts = {21: 0, 23: 0}
        for name, width in (("tcp", 8), ("tcp6", 32)):
            try:
                lines = read_regular_text(self.root / name).splitlines()
                if not lines or "local_address" not in lines[0] or "st" not in lines[0]:
                    raise ValueError("Invalid TCP header")
            except (OSError, UnicodeError):
                unavailable = True
                continue
            except ValueError:
                malformed = True
                continue
            observed_table = True
            for line in lines[1:]:
                try:
                    fields = line.split()
                    if len(fields) < 10:
                        raise ValueError("Invalid TCP record")
                    endpoint = rf"[0-9A-Fa-f]{{{width}}}:[0-9A-Fa-f]{{4}}"
                    if not re.fullmatch(endpoint, fields[1]):
                        raise ValueError("Invalid local endpoint")
                    if not re.fullmatch(endpoint, fields[2]):
                        raise ValueError("Invalid remote endpoint")
                    if not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3]):
                        raise ValueError("Invalid TCP state")
                    if fields[3].upper() == "0A":
                        port = int(fields[1].split(":")[1], 16)
                        if port in {21, 23}:
                            failed = True
                            counts[port] += 1
                except ValueError:
                    # Continue within this table so known forbidden listeners
                    # cannot be hidden by an earlier malformed record.
                    malformed = True
        status = (
            Status.FAIL
            if failed
            else Status.WARN
            if malformed
            else Status.SKIP
            if unavailable
            else Status.PASS
        )
        return self.result(
            status,
            "TCP ports 21/23 in current namespace; alternate ports not assessed",
            evidence=(
                Evidence(
                    EvidenceKey.PORT21,
                    counts[21] if observed_table else EvidenceValue.UNKNOWN,
                ),
                Evidence(
                    EvidenceKey.PORT23,
                    counts[23] if observed_table else EvidenceValue.UNKNOWN,
                ),
                Evidence(
                    EvidenceKey.COVERAGE,
                    EvidenceValue.PARTIAL
                    if unavailable or malformed
                    else EvidenceValue.COMPLETE,
                ),
            ),
        )
