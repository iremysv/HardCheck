"""Best-effort environment labels; no host-scope or privilege guarantees."""

import platform
import re
from dataclasses import dataclass
from pathlib import Path

from hardcheck.safe_io import read_regular_text


@dataclass(frozen=True)
class Environment:
    system: str
    distribution: str = "unknown"
    service_manager: str = "unknown"
    container: bool | None = None


def public_environment(environment: Environment | None) -> dict | None:
    """Only bounded environment markers may cross the reporting boundary."""
    if environment is None:
        return None
    distribution = environment.distribution
    if not isinstance(distribution, str) or not re.fullmatch(
        r"[a-z0-9._-]{1,64}", distribution
    ):
        distribution = "unknown"
    return {
        "system": environment.system
        if environment.system in {
            "Linux", "Darwin", "Windows", "FreeBSD", "OpenBSD", "NetBSD",
        }
        else "unknown",
        "distribution": distribution,
        "service_manager": environment.service_manager
        if environment.service_manager in {"systemd", "openrc", "unknown"}
        else "unknown",
        "container": "detected" if environment.container is True else "unknown",
        "host_namespace_verified": False,
    }


def detect_environment(
    root: Path = Path("/"), system: str | None = None
) -> Environment:
    """Read bounded local markers without sourcing os-release or running commands."""
    system = platform.system() if system is None else system
    if system != "Linux":
        return Environment(system)
    distribution = "unknown"
    try:
        for line in read_regular_text(root / "etc/os-release", 16384).splitlines():
            if line.startswith("ID="):
                value = line[3:].strip().strip('"')
                if re.fullmatch(r"[a-z0-9._-]{1,64}", value):
                    distribution = value
    except (OSError, UnicodeError, ValueError):
        pass
    manager = "unknown"
    try:
        if (root / "run/systemd/system").is_dir():
            manager = "systemd"
        elif (root / "run/openrc").is_dir():
            manager = "openrc"
    except OSError:
        pass
    container = None
    try:
        if (root / ".dockerenv").exists() or (root / "run/.containerenv").exists():
            container = True
        else:
            cgroup = read_regular_text(root / "proc/1/cgroup", 65536)
            if re.search(r"docker|kubepods|containerd|libpod|lxc", cgroup):
                container = True
            # Lack of markers never proves this is the host namespace.
    except (OSError, UnicodeError, ValueError):
        pass
    return Environment(system, distribution, manager, container)
