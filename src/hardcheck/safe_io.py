"""Bounded reads of regular files, without executing or modifying content."""

import os
import stat
from pathlib import Path


def read_regular_text(path: Path, limit: int = 262144) -> str:
    """Reject devices/FIFOs and bound reads, including files growing during read."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("File size limit exceeded")
    return data.decode("utf-8")
