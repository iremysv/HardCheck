"""Conservative, read-only checks of OpenSSH daemon configuration."""

import fnmatch
import glob
import os
import re
import shlex
from dataclasses import dataclass
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
from hardcheck.registry import register_check
from hardcheck.safe_io import read_regular_text

SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")


@dataclass(frozen=True)
class SshConfiguration:
    """Static global settings and a non-sensitive assessment limitation."""

    settings: dict[str, str]
    issue: str = ""


def inspect_ssh_config(
    path: Path, include_root: Path | None = None
) -> SshConfiguration:
    """Expand global Includes; never claim connection-specific Match evaluation.

    Relative Include paths use /etc/ssh, as specified by OpenSSH. Tests can
    inject another root. No commands, environment expansion or writes occur.
    """
    root = include_root if include_root is not None else Path("/etc/ssh")
    settings: dict[str, str] = {}
    active: set[Path] = set()
    files = 0
    total_bytes = 0

    def visit(current: Path, depth: int) -> None:
        nonlocal files, total_bytes
        if depth > 16 or files >= 128:
            raise ValueError("SSH Include resource limit exceeded")
        resolved = current.resolve()
        if resolved in active:
            raise ValueError("SSH Include cycle detected")
        files += 1
        content = read_regular_text(current)
        total_bytes += len(content.encode("utf-8"))
        if total_bytes > 2 * 1024 * 1024:
            raise ValueError("SSH configuration size limit exceeded")
        active.add(resolved)
        try:
            for raw_line in content.splitlines():
                # OpenSSH permits one optional '=' after the keyword. Normalize
                # only that boundary: Include filenames may themselves contain '='.
                line = re.sub(
                    r"^([ \t]*[^ \t=]+)[ \t]*=[ \t]*", r"\1 ", raw_line, count=1
                )
                lexer = shlex.shlex(line, posix=True)
                lexer.whitespace_split = True
                lexer.quotes = '"'
                lexer.escape = ""
                parts = list(lexer)
                if not parts:
                    continue
                directive, *values = parts
                directive = directive.lower()
                if directive == "match":
                    raise ValueError("Match requires connection-specific evaluation")
                if directive == "include":
                    if not values:
                        raise ValueError("Include requires a path")
                    for pattern in values:
                        target = Path(pattern)
                        if not target.is_absolute():
                            target = root / target
                        # glob silently ignores directory permission errors. Scan
                        # explicitly so unreadable Includes cannot produce PASS.
                        if glob.has_magic(str(target.parent)) or "**" in target.name:
                            raise ValueError("Unsupported Include directory pattern")
                        matches = []
                        try:
                            with os.scandir(target.parent) as entries:
                                for index, entry in enumerate(entries):
                                    if index >= 4096:
                                        raise ValueError("Include directory too large")
                                    if entry.name.startswith(".") and not (
                                        target.name.startswith(".")
                                    ):
                                        continue
                                    if fnmatch.fnmatchcase(entry.name, target.name):
                                        matches.append(entry.path)
                                        if len(matches) > 128:
                                            raise ValueError("Too many Include matches")
                        except FileNotFoundError:
                            pass
                        for name in sorted(matches):
                            visit(Path(name), depth + 1)
                elif directive in {
                    "permitrootlogin",
                    "passwordauthentication",
                    "maxauthtries",
                    "permitemptypasswords",
                }:
                    if len(values) != 1:
                        raise ValueError("Invalid SSH directive arguments")
                    settings.setdefault(directive, values[0])
        finally:
            active.remove(resolved)

    try:
        visit(path, 0)
    except (OSError, UnicodeError, ValueError, RuntimeError):
        return SshConfiguration({}, "SSH configuration could not be fully evaluated")
    return SshConfiguration(settings)


def read_ssh_settings(path: Path) -> dict[str, str] | None:
    """Compatibility helper; unsupported configuration yields no settings."""
    result = inspect_ssh_config(path)
    return result.settings if not result.issue else None


class SshSettingCheck(BaseCheck):
    """Check one global sshd_config directive."""

    category = "ssh"
    severity = Severity.HIGH
    reference = "https://man.openbsd.org/sshd_config"
    setting: str

    def __init__(
        self, config_path: Path = SSH_CONFIG_PATH, include_root: Path | None = None
    ) -> None:
        """Allow dependency injection of the configuration path."""
        self.config_path = config_path
        self.include_root = include_root

    def is_secure(self, value: str) -> bool:
        """Return whether a directive value satisfies the policy."""
        raise NotImplementedError

    def run(self) -> CheckResult:
        """Inspect the configuration without making changes."""
        try:
            self.config_path.stat()
        except FileNotFoundError:
            return self.result(Status.SKIP, "SSH configuration is absent")
        except OSError:
            return self.result(Status.WARN, "SSH configuration is unavailable")
        config = inspect_ssh_config(self.config_path, self.include_root)
        if config.issue:
            return self.result(Status.WARN, config.issue)
        value = config.settings.get(self.setting.lower())
        if value is None:
            return self.result(Status.WARN, "Directive is not explicitly configured")
        observed: EvidenceValue | int = EvidenceValue.INVALID
        if value in {"yes", "no"}:
            observed = EvidenceValue(value)
        elif self.setting == "MaxAuthTries" and re.fullmatch(r"[0-9]{1,10}", value):
            observed = int(value)
        return self.result(
            Status.PASS if self.is_secure(value) else Status.FAIL,
            evidence=(Evidence(EvidenceKey.SETTING, observed),),
        )


@register_check
class SshRootLoginDisabledCheck(SshSettingCheck):
    """Require PermitRootLogin to be disabled."""

    check_id = "SSH-001"
    setting = "PermitRootLogin"

    def is_secure(self, value: str) -> bool:
        """Require the value no."""
        return value == "no"


@register_check
class SshPasswordAuthenticationDisabledCheck(SshSettingCheck):
    """Require password authentication to be disabled."""

    check_id = "SSH-002"
    setting = "PasswordAuthentication"

    def is_secure(self, value: str) -> bool:
        """Require the value no."""
        return value == "no"


@register_check
class SshMaxAuthTriesCheck(SshSettingCheck):
    """Limit SSH authentication attempts to four."""

    check_id = "SSH-003"
    setting = "MaxAuthTries"

    def is_secure(self, value: str) -> bool:
        """Require an integer between one and four."""
        try:
            return bool(re.fullmatch(r"[0-9]{1,10}", value)) and 1 <= int(value) <= 4
        except ValueError:
            return False


@register_check
class SshEmptyPasswordsDisabledCheck(SshSettingCheck):
    """Require PermitEmptyPasswords to be disabled."""

    check_id = "SSH-004"
    setting = "PermitEmptyPasswords"

    def is_secure(self, value: str) -> bool:
        """Require the value no."""
        return value == "no"
