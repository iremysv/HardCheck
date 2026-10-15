"""SSH Include precedence, failure boundaries and resource limits."""

import os

import pytest

from hardcheck.checks.ssh import SshRootLoginDisabledCheck, inspect_ssh_config
from hardcheck.models import Status


def test_include_lexical_order_and_global_first_value(tmp_path):
    directory = tmp_path / "conf.d"
    directory.mkdir()
    (directory / "20.conf").write_text("PermitRootLogin no\n")
    (directory / "10.conf").write_text('PermitRootLogin "yes" # comment\n')
    config = tmp_path / "sshd_config"
    config.write_text("Include conf.d/*.conf\nPermitRootLogin no\n")
    assert SshRootLoginDisabledCheck(config, tmp_path).run().status == Status.FAIL
    config.write_text("PermitRootLogin no\nInclude conf.d/*.conf\n")
    assert SshRootLoginDisabledCheck(config, tmp_path).run().status == Status.PASS


def test_nested_relative_include_uses_fixed_root(tmp_path):
    directory = tmp_path / "conf.d"
    directory.mkdir()
    (directory / "a.conf").write_text("Include policy.conf\n")
    (tmp_path / "policy.conf").write_text("PermitRootLogin no\n")
    config = tmp_path / "sshd_config"
    config.write_text("Include conf.d/a.conf\n")
    assert SshRootLoginDisabledCheck(config, tmp_path).run().status == Status.PASS


@pytest.mark.parametrize("content", [
    "Include sshd_config\n",
    "Match all\nPermitRootLogin no\n",
    "PermitRootLogin no extra\n",
    'PermitRootLogin "no\n',
    "Include\n",
    "PermitRootLogin no\nInclude missing.conf\nMatch all\n",
])
def test_ambiguous_config_never_passes(tmp_path, content):
    config = tmp_path / "sshd_config"
    config.write_text(content)
    result = SshRootLoginDisabledCheck(config, tmp_path).run()
    assert result.status == Status.WARN
    assert result.detail
    assert not inspect_ssh_config(config, tmp_path).settings


def test_unmatched_glob_preserves_explicit_value(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Include absent/*.conf\nPermitRootLogin no\n")
    assert SshRootLoginDisabledCheck(config, tmp_path).run().status == Status.PASS


def test_unreadable_include_discards_partial_settings(tmp_path):
    config = tmp_path / "sshd_config"
    (tmp_path / "invalid").write_bytes(b"\xff")
    config.write_text("PermitRootLogin no\nInclude invalid\n")
    assert SshRootLoginDisabledCheck(config, tmp_path).run().status == Status.WARN


def test_oversized_file_and_fifo_are_not_read_as_config(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("#" * 262145)
    assert SshRootLoginDisabledCheck(config).run().status == Status.WARN
    config.unlink()
    os.mkfifo(config)
    assert SshRootLoginDisabledCheck(config).run().status == Status.WARN


def test_depth_limit(tmp_path):
    for index in range(19):
        (tmp_path / str(index)).write_text(f"Include {index + 1}\n")
    assert inspect_ssh_config(tmp_path / "0", tmp_path).issue


def test_expansion_limit(tmp_path):
    directory = tmp_path / "parts"
    directory.mkdir()
    for index in range(129):
        (directory / str(index)).write_text("# empty")
    config = tmp_path / "sshd_config"
    config.write_text("Include parts/*\n")
    assert inspect_ssh_config(config, tmp_path).issue


def test_permission_failure_is_warning(tmp_path, monkeypatch):
    import hardcheck.checks.ssh as ssh

    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin no\n")

    def denied(*args):
        raise PermissionError

    monkeypatch.setattr(ssh, "read_regular_text", denied)
    assert SshRootLoginDisabledCheck(config).run().status == Status.WARN
