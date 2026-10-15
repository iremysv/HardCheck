"""Conservative, read-only checks of OpenSSH daemon configuration."""

from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import CheckResult, Severity, Status
from hardcheck.registry import register_check

SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")


def read_ssh_settings(path: Path) -> dict[str, str] | None:
    """Read global directives; return empty settings for unsupported constructs."""
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    settings: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        directive = parts[0].lower()
        if directive in {"include", "match"}:
            return {}
        if len(parts) > 1:
            settings.setdefault(directive, parts[1].lower())
    return settings


class SshSettingCheck(BaseCheck):
    """Check one global sshd_config directive."""

    category = "ssh"
    severity = Severity.HIGH
    reference = "https://man.openbsd.org/sshd_config"
    setting: str

    def __init__(self, config_path: Path = SSH_CONFIG_PATH) -> None:
        """Allow dependency injection of the configuration path."""
        self.config_path = config_path

    def is_secure(self, value: str) -> bool:
        """Return whether a directive value satisfies the policy."""
        raise NotImplementedError

    def run(self) -> CheckResult:
        """Inspect the configuration without making changes."""
        settings = read_ssh_settings(self.config_path)
        if settings is None:
            return self.result(Status.SKIP)
        value = settings.get(self.setting.lower())
        if value is None:
            return self.result(Status.WARN)
        return self.result(Status.PASS if self.is_secure(value) else Status.FAIL)


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
            return 1 <= int(value) <= 4
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
