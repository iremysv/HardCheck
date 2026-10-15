"""Local account checks; account names and password fields never enter results."""

import re
from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import CheckResult, Severity, Status
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
        for row in rows:
            if len(row) != self.fields or not row[0] or row[0] in names:
                return self.result(Status.WARN, "Malformed local account records")
            if row[0].startswith(("+", "-")) or any(c.isspace() for c in row[0]):
                return self.result(Status.WARN, "Unsupported local account records")
            names.add(row[0])
        status = self.evaluate(rows)
        return self.result(status, "Local file assessment; network accounts excluded")


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
        privileged = [row[0] for row in rows if int(row[2]) == 0]
        return Status.PASS if privileged == ["root"] else Status.FAIL
