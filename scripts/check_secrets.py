"""Scan tracked regular files offline; report locations without secret values."""

import json
import shutil
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path


class ScanError(ValueError):
    """An incomplete scan must never be reported as clean."""


def tracked_files(root: Path) -> list[str]:
    """Use Git's NUL-separated index and refuse links or unreadable file types."""
    executable = shutil.which("git")
    if executable is None:
        raise ScanError("Git executable is unavailable")
    # The fixed argv cannot be changed by file names or shell syntax.
    completed = subprocess.run(  # nosec B603
        [executable, "ls-files", "-z", "--cached"],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=15,
    )
    paths = completed.stdout.decode("utf-8").split("\0")
    paths = sorted(set(path for path in paths if path))
    if not paths:
        raise ScanError("No tracked files")
    # Ignore rules also guard the index: git add -f must not bypass local-data policy.
    ignored = subprocess.run(  # nosec B603
        [executable, "check-ignore", "--no-index", "--stdin", "-z"],
        cwd=root,
        input=("\0".join(paths) + "\0").encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=15,
    )
    if ignored.returncode not in (0, 1) or ignored.stdout:
        raise ScanError("Index contains ignored files or ignore check failed")
    for path in paths:
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ScanError("Unsafe index path")
        if not (root / relative).resolve().is_relative_to(root.resolve()):
            raise ScanError("Tracked path escapes repository")
        if not stat.S_ISREG((root / relative).lstat().st_mode):
            raise ScanError("Only tracked regular files are supported")
    return paths


def scan(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    """The detector's scan command exits zero on findings; enforce failure here."""
    paths = tracked_files(root)
    # No credential verification: candidate values must never reach a service.
    completed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "detect_secrets",
            "scan",
            "--no-verify",
            "--all-files",
            "--",
            *("./" + path for path in paths),
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if completed.returncode or completed.stderr:
        raise ScanError("Secret detector did not complete cleanly")
    document = json.loads(completed.stdout)
    if not isinstance(document, dict) or not isinstance(document.get("results"), dict):
        raise ScanError("Invalid detector response")
    findings = []
    for path, items in document["results"].items():
        for item in items:
            findings.append((path, int(item["line_number"]), str(item["type"])))
    return len(paths), sorted(findings)


def main() -> int:
    """Scan the repository index; ignored local files and history are out of scope."""
    root = Path(__file__).resolve().parents[1]
    try:
        count, findings = scan(root)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Secret scan could not complete; result is not clean.", file=sys.stderr)
        return 2
    for path, line, detector in findings:
        print(json.dumps({"path": path, "line": line, "detector": detector}))
    if findings:
        print(f"Secret scan: {len(findings)} finding(s); values withheld.")
        return 1
    print(f"Secret scan: {count} tracked files; no findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
