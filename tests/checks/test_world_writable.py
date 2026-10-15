"""Bounded filesystem traversal, without host filesystem scans."""

import os
from pathlib import Path

from hardcheck.checks.world_writable import WorldWritableEtcCheck
from hardcheck.models import Status


def test_world_writable_pass_and_fail(tmp_path):
    directory = tmp_path / "nested"
    directory.mkdir()
    file = directory / "private-name"
    file.write_text("private-content")
    file.chmod(0o644)
    assert WorldWritableEtcCheck(tmp_path).run().status == Status.PASS
    file.chmod(0o646)
    before = file.stat()
    result = WorldWritableEtcCheck(tmp_path).run()
    assert result.status == Status.FAIL
    assert "private-name" not in repr(result)
    assert "private-content" not in repr(result)
    assert file.stat().st_mode == before.st_mode
    assert file.stat().st_mtime_ns == before.st_mtime_ns


def test_symlink_escape_and_fifo_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "unsafe").write_text("fixture")
    (outside / "unsafe").chmod(0o666)
    root = tmp_path / "etc"
    root.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    os.mkfifo(root / "fifo")
    assert WorldWritableEtcCheck(root).run().status == Status.PASS
    assert WorldWritableEtcCheck(root / "escape").run().status == Status.WARN


def test_limits_never_produce_pass(tmp_path):
    (tmp_path / "one").write_text("fixture")
    (tmp_path / "two").write_text("fixture")
    assert WorldWritableEtcCheck(tmp_path, max_entries=1).run().status == Status.WARN
    nested = tmp_path / "directory"
    nested.mkdir()
    assert WorldWritableEtcCheck(tmp_path, max_depth=0).run().status == Status.WARN


def test_missing_and_denied_directory(tmp_path, monkeypatch):
    import hardcheck.checks.world_writable as module

    assert WorldWritableEtcCheck(tmp_path / "missing").run().status == Status.SKIP
    original = module.os.scandir
    private = tmp_path / "private"
    private.mkdir()
    inode = private.stat().st_ino

    def denied(fd):
        if os.fstat(fd).st_ino == inode:
            raise PermissionError
        return original(fd)

    monkeypatch.setattr(module.os, "scandir", denied)
    result = WorldWritableEtcCheck(tmp_path).run()
    assert result.status == Status.WARN
    assert "incomplete" in result.detail


def test_directory_replacement_with_symlink_is_not_followed(tmp_path, monkeypatch):
    import hardcheck.checks.world_writable as module

    root = tmp_path / "etc"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "unsafe").write_text("fixture")
    (outside / "unsafe").chmod(0o666)
    original = os.open

    def swapped(path, flags, **kwargs):
        if path == "nested":
            nested.rmdir()
            nested.symlink_to(outside, target_is_directory=True)
        return original(path, flags, **kwargs)

    monkeypatch.setattr(module.os, "open", swapped)
    assert WorldWritableEtcCheck(root).run().status == Status.WARN


def test_known_failure_is_not_hidden_by_incomplete_scan(tmp_path, monkeypatch):
    import hardcheck.checks.world_writable as module

    file = tmp_path / "unsafe"
    file.write_text("fixture")
    file.chmod(0o666)
    private = tmp_path / "private"
    private.mkdir()
    inode = private.stat().st_ino
    original = os.scandir

    def denied(fd):
        if os.fstat(fd).st_ino == inode:
            raise PermissionError
        return original(fd)

    monkeypatch.setattr(module.os, "scandir", denied)
    result = WorldWritableEtcCheck(tmp_path).run()
    assert result.status == Status.FAIL
    assert "incomplete" in result.detail


def test_open_failure_is_warning(tmp_path, monkeypatch):
    import hardcheck.checks.world_writable as module

    def denied(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(module.os, "open", denied)
    assert WorldWritableEtcCheck(Path(tmp_path)).run().status == Status.WARN
