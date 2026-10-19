"""Local account checks; account names and password fields never enter results."""

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


class AccountCheck(BaseCheck):
    """Inspect bounded local account files, without consulting network NSS."""

    category = "users"
    severity = Severity.HIGH
    reference = "https://man7.org/linux/man-pages/man5/shadow.5.html"
    fields: int

    def __init__(self, path: Path) -> None:
        self.path = path

    def evaluate(self, rows: list[list[str]]) -> Status:
        raise NotImplementedError

    def run(self) -> CheckResult:
        try:
            content = read_regular_text(self.path)
        except FileNotFoundError:
            return self.result(Status.SKIP, "Local account file is absent")
        except (OSError, UnicodeError, ValueError):
            return self.result(Status.WARN, "Local account file cannot be evaluated")
        rows = [line.split(":") for line in content.splitlines() if line]
        names: set[str] = set()
        if not rows:
            return self.result(Status.WARN, "Local account file is empty")
        valid_rows = []
        partial = False
        for row in rows:
            if len(row) != self.fields or not row[0]:
                partial = True
                continue
            if row[0].startswith(("+", "-")) or any(c.isspace() for c in row[0]):
                partial = True
                continue
            if row[0] in names:
                partial = True
            names.add(row[0])
            if self.evaluate([row]) == Status.WARN:
                partial = True
                continue
            valid_rows.append(row)
        if self.check_id == "USR-001":
            matches = sum(row[1] == "" for row in valid_rows)
        else:
            matches = sum(
                int(row[2]) == 0 and row[0] != "root" for row in valid_rows
            )
            # Absence can only be established from a complete inventory.
            if not partial:
                matches += int(not any(
                    row[0] == "root" and int(row[2]) == 0 for row in valid_rows
                ))
        status = Status.FAIL if matches else Status.WARN if partial else Status.PASS
        facts = [Evidence(EvidenceKey.RECORDS, len(valid_rows))]
        if partial:
            facts.append(Evidence(EvidenceKey.COVERAGE, EvidenceValue.PARTIAL))
        if status in {Status.PASS, Status.FAIL}:
            facts.append(Evidence(EvidenceKey.MATCHES, matches))
        return self.result(
            status,
            "Local file assessment; network accounts excluded",
            evidence=tuple(facts),
        )


class EmptyPasswordCheck(AccountCheck):
    """Require every local shadow password field to be nonempty."""

    check_id = "USR-001"
    fields = 9

    def __init__(self, path: Path = Path("/etc/shadow")) -> None:
        super().__init__(path)

    def evaluate(self, rows: list[list[str]]) -> Status:
        # Locked fields (!, !!, *) are nonempty. Never emit values or usernames.
        return Status.FAIL if any(row[1] == "" for row in rows) else Status.PASS


class RootUidCheck(AccountCheck):
    """Require exactly one UID-zero account, named root."""

    check_id = "USR-002"
    fields = 7
    severity = Severity.CRITICAL
    reference = "https://man7.org/linux/man-pages/man5/passwd.5.html"

    def __init__(self, path: Path = Path("/etc/passwd")) -> None:
        super().__init__(path)

    def evaluate(self, rows: list[list[str]]) -> Status:
        if any(not re.fullmatch(r"[0-9]{1,10}", row[2]) for row in rows):
            return Status.WARN
        if any(not re.fullmatch(r"[0-9]{1,10}", row[3]) for row in rows):
            return Status.WARN
        if any(int(row[index]) > 4294967294 for row in rows for index in (2, 3)):
            return Status.WARN
        privileged = [row[0] for row in rows if int(row[2]) == 0]
        return Status.PASS if privileged == ["root"] else Status.FAIL
