"""Filesystem metadata checks; no target file contents are read or modified."""

import stat
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


class MetadataCheck(BaseCheck):
    """Evaluate lstat metadata without following the final symlink."""

    category = "filesystem"
    severity = Severity.HIGH
    reference = "https://man7.org/linux/man-pages/man7/inode.7.html"

    def __init__(self, path: Path, expected_uid: int = 0) -> None:
        self.path = path
        self.expected_uid = expected_uid

    def evaluate(self, info) -> bool:
        raise NotImplementedError

    def run(self) -> CheckResult:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return self.result(Status.SKIP, "Filesystem target is absent")
        except OSError:
            return self.result(Status.WARN, "Filesystem metadata is unavailable")
        if stat.S_ISLNK(info.st_mode):
            return self.result(Status.WARN, "Symlink target is not assessed")
        secure = info.st_uid == self.expected_uid and self.evaluate(info)
        return self.result(
            Status.PASS if secure else Status.FAIL,
            "Owner and mode bits assessed; ACLs and parent paths not assessed",
            evidence=(
                Evidence(EvidenceKey.OWNER_UID, info.st_uid),
                Evidence(EvidenceKey.MODE, stat.S_IMODE(info.st_mode)),
                Evidence(
                    EvidenceKey.STICKY,
                    EvidenceValue.YES
                    if info.st_mode & stat.S_ISVTX
                    else EvidenceValue.NO,
                ),
            ),
        )


class PasswdPermissionsCheck(MetadataCheck):
    """Require root-owned /etc/passwd with exact mode 0644."""

    check_id = "FS-001"

    def __init__(self, path: Path = Path("/etc/passwd"), expected_uid: int = 0):
        super().__init__(path, expected_uid)

    def evaluate(self, info) -> bool:
        return stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644


class ShadowPermissionsCheck(MetadataCheck):
    """Require root ownership and mode bits that are a subset of 0640."""

    check_id = "FS-002"
    severity = Severity.CRITICAL

    def __init__(self, path: Path = Path("/etc/shadow"), expected_uid: int = 0):
        super().__init__(path, expected_uid)

    def evaluate(self, info) -> bool:
        return stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) & ~0o640 == 0


class TmpStickyCheck(MetadataCheck):
    """Require a root-owned /tmp directory with its sticky bit set."""

    check_id = "FS-003"
    reference = "https://man7.org/linux/man-pages/man2/chmod.2.html"

    # Inspect the existing directory with lstat; never create temporary files.
    def __init__(
        self,
        path: Path = Path("/tmp"),  # nosec B108
        expected_uid: int = 0,
    ):
        super().__init__(path, expected_uid)

    def evaluate(self, info) -> bool:
        return stat.S_ISDIR(info.st_mode) and bool(info.st_mode & stat.S_ISVTX)
