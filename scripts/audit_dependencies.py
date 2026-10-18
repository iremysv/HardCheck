"""Audit the exact installed environment without resolving or skipping dependencies."""

import subprocess  # nosec B404
import sys
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory

from packaging.utils import canonicalize_name
from packaging.version import Version


def resolved_requirements() -> list[str]:
    """Only exclude this unpublished project, whose source is checked separately."""
    pins = {}
    for distribution in metadata.distributions():
        name = canonicalize_name(distribution.metadata["Name"], validate=True)
        if name == "hardcheck":
            continue
        version = str(Version(distribution.version))
        if name in pins and pins[name] != version:
            raise ValueError("Conflicting installed distributions")
        pins[name] = version
    if not pins:
        raise ValueError("No installed dependencies to audit")
    return [f"{name}=={version}" for name, version in sorted(pins.items())]


def main() -> int:
    """Send names/versions to the advisory service, never source or credentials."""
    try:
        pins = resolved_requirements()
        with TemporaryDirectory(prefix="hardcheck-dependencies-") as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("\n".join(pins) + "\n", encoding="utf-8")
            # Fixed module and flags; pins were validated as package names/versions.
            completed = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    "-m",
                    "pip_audit",
                    "--requirement",
                    str(path),
                    "--disable-pip",
                    "--no-deps",
                    "--strict",
                    "--timeout",
                    "15",
                    "--progress-spinner",
                    "off",
                ],
                check=False,
                timeout=180,
            )
        return completed.returncode
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("Dependency audit could not complete.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
