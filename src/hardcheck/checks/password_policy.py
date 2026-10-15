"""Static password defaults, without claiming PAM or existing-account enforcement."""

import os
import re
from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import CheckResult, Severity, Status
from hardcheck.safe_io import read_regular_text


def integer(value: str) -> int:
    """Accept only bounded ASCII decimal settings."""
    if not re.fullmatch(r"-?[0-9]{1,9}", value):
        raise ValueError("Invalid numeric setting")
    return int(value)


class PasswordAgeCheck(BaseCheck):
    """Check the new-account PASS_MAX_DAYS default, not existing accounts."""

    check_id = "USR-003"
    category = "users"
    severity = Severity.MEDIUM
    reference = "https://man7.org/linux/man-pages/man5/login.defs.5.html"

    def __init__(self, path: Path = Path("/etc/login.defs")) -> None:
        self.path = path

    def run(self) -> CheckResult:
        try:
            content = read_regular_text(self.path)
            values = []
            for line in content.splitlines():
                parts = line.split("#", 1)[0].split()
                if parts and parts[0] == "PASS_MAX_DAYS":
                    if len(parts) != 2:
                        raise ValueError("Invalid PASS_MAX_DAYS")
                    values.append(integer(parts[1]))
            if len(values) != 1:
                return self.result(Status.WARN, "Missing or ambiguous PASS_MAX_DAYS")
        except FileNotFoundError:
            return self.result(Status.SKIP, "Password default file is absent")
        except (OSError, UnicodeError, ValueError):
            return self.result(Status.WARN, "Password defaults cannot be evaluated")
        status = Status.PASS if 1 <= values[0] <= 90 else Status.FAIL
        return self.result(
            status, "New-account default only; existing accounts excluded"
        )


class PasswordLengthCheck(BaseCheck):
    """Check configured libpwquality length after positive character credits."""

    check_id = "USR-004"
    category = "users"
    severity = Severity.HIGH
    reference = (
        "https://github.com/libpwquality/libpwquality/"
        "blob/master/doc/man/pwquality.conf.5.pod"
    )

    def __init__(self, path: Path = Path("/etc/security/pwquality.conf")) -> None:
        self.path = path

    def run(self) -> CheckResult:
        try:
            files: list[Path] = []
            directory = self.path.with_name(self.path.name + ".d")
            try:
                with os.scandir(directory) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 1024:
                            raise ValueError("Too many policy directory entries")
                        if entry.name.endswith(".conf"):
                            files.append(Path(entry.path))
                            if len(files) > 128:
                                raise ValueError("Too many policy files")
            except FileNotFoundError:
                pass
            files.sort()
            # Main file overrides snippets. Missing main/fallback handling is
            # intentionally uncertain instead of assuming distribution defaults.
            files.append(self.path)
            settings: dict[str, int] = {}
            relevant = {
                "minlen", "dcredit", "ucredit", "lcredit", "ocredit", "enforcing"
            }
            total = 0
            for path in files:
                content = read_regular_text(path, 65536)
                total += len(content.encode("utf-8"))
                if total > 1024 * 1024:
                    raise ValueError("Policy size limit exceeded")
                for raw in content.splitlines():
                    line = raw.split("#", 1)[0].strip()
                    if not line:
                        continue
                    key, separator, value = line.partition("=")
                    key = key.strip()
                    if key and key.split()[0] in relevant and key not in relevant:
                        raise ValueError("Invalid policy key syntax")
                    if key in relevant:
                        if not separator:
                            raise ValueError("Invalid policy assignment")
                        settings[key] = integer(value.strip())
            if "minlen" not in settings:
                return self.result(Status.WARN, "No explicit minlen policy")
            # libpwquality defaults all credits to zero; positive credits can
            # reduce actual length. Use a conservative lower bound.
            credits = sum(max(0, settings.get(key, 0)) for key in (
                "dcredit", "ucredit", "lcredit", "ocredit"
            ))
            secure = settings["minlen"] - credits >= 12
            secure = secure and settings.get("enforcing", 1) != 0
        except FileNotFoundError:
            return self.result(Status.WARN, "Password quality policy is incomplete")
        except (OSError, UnicodeError, ValueError):
            return self.result(
                Status.WARN, "Password quality policy cannot be evaluated"
            )
        return self.result(
            Status.PASS if secure else Status.FAIL,
            "Static libpwquality policy; PAM activation and overrides not assessed",
        )
