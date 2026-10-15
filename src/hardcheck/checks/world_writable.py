"""Bounded, descriptor-relative traversal of local regular-file mode bits."""

import os
import stat
from pathlib import Path

from hardcheck.checks.base import BaseCheck
from hardcheck.models import CheckResult, Severity, Status


class TraversalLimit(ValueError):
    """Traversal could not cover the configured tree."""


class WorldWritableEtcCheck(BaseCheck):
    """Detect world-writable regular files; never follow symlinks or mounts."""

    check_id = "FS-004"
    category = "filesystem"
    severity = Severity.HIGH
    reference = "https://man7.org/linux/man-pages/man7/inode.7.html"

    def __init__(
        self, root: Path = Path("/etc"), *, max_entries: int = 20000,
        max_depth: int = 64,
    ) -> None:
        self.root = root
        self.max_entries = max_entries
        self.max_depth = max_depth

    def run(self) -> CheckResult:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(self.root, flags)
        except FileNotFoundError:
            return self.result(Status.SKIP, "Scan directory is absent")
        except OSError:
            return self.result(Status.WARN, "Scan directory cannot be evaluated")
        count = 0
        findings = 0
        incomplete = False
        visited: set[tuple[int, int]] = set()
        device = 0

        def visit(fd: int, depth: int) -> None:
            nonlocal count, findings, incomplete
            if depth > self.max_depth:
                raise TraversalLimit
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if identity in visited or info.st_dev != device:
                incomplete = True
                return
            visited.add(identity)
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    if count > self.max_entries:
                        raise TraversalLimit
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        if metadata.st_dev != device:
                            incomplete = True
                        elif stat.S_ISREG(metadata.st_mode):
                            if metadata.st_mode & stat.S_IWOTH:
                                findings += 1
                        elif stat.S_ISDIR(metadata.st_mode):
                            child = os.open(entry.name, flags, dir_fd=fd)
                            try:
                                # Detect replacement between stat and open.
                                actual = os.fstat(child)
                                if (actual.st_dev, actual.st_ino) != (
                                    metadata.st_dev, metadata.st_ino
                                ):
                                    incomplete = True
                                else:
                                    visit(child, depth + 1)
                            finally:
                                os.close(child)
                        # Symlinks and nonregular files are deliberately excluded.
                    except OSError:
                        incomplete = True

        try:
            device = os.fstat(descriptor).st_dev
            visit(descriptor, 0)
        except (OSError, TraversalLimit):
            incomplete = True
        finally:
            os.close(descriptor)
        status = Status.FAIL if findings else Status.WARN if incomplete else Status.PASS
        coverage = "incomplete" if incomplete else "complete within declared scope"
        return self.result(
            status,
            f"World-writable regular files: {findings}; traversal {coverage}; "
            "symlinks and special files excluded; ACLs not assessed",
        )
