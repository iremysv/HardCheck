"""Allowlisted read-only queries with fixed environment and bounded output/time."""

import os
import selectors
import signal
import stat

# Fixed read-only argv; no shell or PATH lookup.
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path

QUERIES = {
    "ufw": ("ufw", ("status",)),
    "nft": ("nft", ("--json", "list", "ruleset")),
    "iptables": ("iptables", ("-S", "INPUT")),
    "packages-deb": (
        "dpkg-query",
        ("-W", "-f=${binary:Package}\\t${db:Status-Status}\\n"),
    ),
    "packages-rpm": ("rpm", ("-qa", "--qf", "%{NAME}\\n")),
    "unit-files": ("systemctl", ("list-unit-files", "--no-legend", "--no-pager")),
    "units": ("systemctl", ("list-units", "--all", "--no-legend", "--no-pager")),
}
TRUSTED_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


@dataclass(frozen=True)
class CommandResult:
    state: str
    output: str = ""
    code: int | None = None


def resolve_binary(name: str) -> Path | None:
    for directory in TRUSTED_DIRS:
        path = Path(directory) / name
        try:
            info = path.stat()
            if (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022
                and os.access(path, os.X_OK)
            ):
                return path
        except OSError:
            continue
    return None


def run_query(name: str, *, timeout: float = 3, limit: int = 1048576) -> CommandResult:
    """No shell, PATH lookup, user-supplied arguments or privilege elevation."""
    if name not in QUERIES:
        return CommandResult("error")
    binary, arguments = QUERIES[name]
    path = resolve_binary(binary)
    if path is None:
        return CommandResult("missing")
    try:
        # Only QUERIES supplies arguments; configuration never supplies commands.
        process = subprocess.Popen(  # nosec B603
            [str(path), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
            cwd="/",
            close_fds=True,
            env={
                "PATH": ":".join(TRUSTED_DIRS),
                "LC_ALL": "C",
                "SYSTEMD_COLORS": "0",
                "SYSTEMD_PAGER": "cat",
            },
        )
    except OSError:
        return CommandResult("error")
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return CommandResult("error")
                if not selector.select(remaining):
                    return CommandResult("error")
                chunk = os.read(process.stdout.fileno(), min(4096, limit + 1))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    return CommandResult("error")
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return CommandResult("done", data.decode("utf-8"), code)
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return CommandResult("error")
    finally:
        # Also terminate any descendant retaining the pipe after parent exit.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
