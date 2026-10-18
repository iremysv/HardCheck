"""Filesystem mode and ownership tests use temporary fixtures only."""

import os
import stat
from pathlib import Path

import pytest

from hardcheck.checks.filesystem import (
    PasswdPermissionsCheck,
    ShadowPermissionsCheck,
    TmpStickyCheck,
)
from hardcheck.models import Status


@pytest.mark.parametrize(("check", "mode", "expected"), [
    (PasswdPermissionsCheck, 0o644, Status.PASS),
    (PasswdPermissionsCheck, 0o666, Status.FAIL),
    (PasswdPermissionsCheck, 0o600, Status.FAIL),
    (ShadowPermissionsCheck, 0o640, Status.PASS),
    (ShadowPermissionsCheck, 0o600, Status.PASS),
    (ShadowPermissionsCheck, 0o400, Status.PASS),
    (ShadowPermissionsCheck, 0o000, Status.PASS),
    (ShadowPermissionsCheck, 0o604, Status.FAIL),
    (ShadowPermissionsCheck, 0o620, Status.FAIL),
    (ShadowPermissionsCheck, 0o644, Status.FAIL),
])
def test_regular_file_permissions(tmp_path, check, mode, expected):
    path = tmp_path / "target"
    path.write_text("fixture content")
    path.chmod(mode)
    before = path.stat()
    assert check(path, os.getuid()).run().status == expected
    after = path.stat()
    assert (before.st_mode, before.st_mtime_ns) == (after.st_mode, after.st_mtime_ns)


@pytest.mark.parametrize("special", [stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX])
@pytest.mark.parametrize("check,base_mode", [
    (PasswdPermissionsCheck, 0o644), (ShadowPermissionsCheck, 0o600),
])
def test_special_permission_bits_fail(monkeypatch, check, base_mode, special):
    # Some temporary filesystems strip setuid bits on chmod. Inject metadata so
    # the security assertion is exercised independently of the host mount policy.
    info = os.stat_result(
        (stat.S_IFREG | base_mode | special, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    )
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    assert check(Path("synthetic-target")).run().status == Status.FAIL


@pytest.mark.parametrize(("mode", "status"), [
    (0o1777, Status.PASS), (0o777, Status.FAIL), (0o1700, Status.PASS),
])
def test_sticky_bit(tmp_path, mode, status):
    path = tmp_path / "tmp"
    path.mkdir()
    path.chmod(mode)
    assert TmpStickyCheck(path, os.getuid()).run().status == status


@pytest.mark.parametrize("check", [
    PasswdPermissionsCheck, ShadowPermissionsCheck, TmpStickyCheck,
])
def test_missing_symlink_owner_and_errors(tmp_path, monkeypatch, check):
    from pathlib import Path

    path = tmp_path / "target"
    assert check(path).run().status == Status.SKIP
    target = tmp_path / "real"
    target.write_text("private fixture")
    path.symlink_to(target)
    assert check(path).run().status == Status.WARN
    path.unlink()
    path.write_text("fixture")
    path.chmod(0o644)
    assert check(path, os.getuid() + 1).run().status == Status.FAIL

    def denied(*args):
        raise PermissionError

    monkeypatch.setattr(Path, "lstat", denied)
    assert check(path).run().status == Status.WARN


def test_wrong_target_types(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    directory.chmod(0o644)
    assert PasswdPermissionsCheck(directory, os.getuid()).run().status == Status.FAIL
    directory.chmod(0o700)
    file = tmp_path / "file"
    file.write_text("fixture")
    file.chmod(0o1700)
    assert TmpStickyCheck(file, os.getuid()).run().status == Status.FAIL
