"""Unit tests for SSH checks using temporary files."""

import pytest

from hardcheck.checks.ssh import (
    SshEmptyPasswordsDisabledCheck,
    SshMaxAuthTriesCheck,
    SshPasswordAuthenticationDisabledCheck,
    SshRootLoginDisabledCheck,
)
from hardcheck.models import Status


@pytest.mark.parametrize(
    ("check_class", "directive", "safe", "unsafe"),
    [
        (SshRootLoginDisabledCheck, "PermitRootLogin", "no", "yes"),
        (SshPasswordAuthenticationDisabledCheck, "PasswordAuthentication", "no", "yes"),
        (SshMaxAuthTriesCheck, "MaxAuthTries", "4", "6"),
        (SshEmptyPasswordsDisabledCheck, "PermitEmptyPasswords", "no", "yes"),
    ],
)
def test_pass_and_fail(tmp_path, check_class, directive, safe, unsafe):
    """Test safe and unsafe settings without accessing host configuration."""
    config = tmp_path / "sshd_config"
    config.write_text(f"{directive} {safe}\n", encoding="utf-8")
    assert check_class(config).run().status == Status.PASS
    config.write_text(f"{directive} {unsafe}\n", encoding="utf-8")
    assert check_class(config).run().status == Status.FAIL


def test_missing_file_is_skipped(tmp_path):
    """Missing files should yield SKIP instead of raising."""
    assert SshRootLoginDisabledCheck(tmp_path / "missing").run().status == Status.SKIP


def test_missing_directive_is_warning(tmp_path):
    """Missing settings must not be counted as PASS."""
    config = tmp_path / "sshd_config"
    config.write_text("# empty\n", encoding="utf-8")
    assert SshRootLoginDisabledCheck(config).run().status == Status.WARN


def test_include_is_conservative(tmp_path):
    """Included configuration should not create a false PASS."""
    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin no\nInclude conf.d/*.conf\n", encoding="utf-8")
    assert SshRootLoginDisabledCheck(config).run().status == Status.WARN
