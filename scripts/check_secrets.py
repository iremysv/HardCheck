"""Scan staged regular-file blobs offline; never report secret values."""

import json
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


class ScanError(ValueError):
    """An incomplete scan must never be reported as clean."""


def reject_ignored(
    root: Path, paths: list[str], work_tree: Path | None = None
) -> None:
    """Check ignore rules from the selected tree, retaining Git's other excludes."""
    executable = shutil.which("git")
    if executable is None:
        raise ScanError("Git executable is unavailable")
    arguments = [executable]
    if work_tree is not None:
        arguments.extend(["--work-tree", str(work_tree)])
    ignored = subprocess.run(  # nosec B603
        [*arguments, "check-ignore", "--no-index", "--stdin", "-z"],
        cwd=root,
        input=("\0".join(paths) + "\0").encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=15,
    )
    if ignored.returncode not in (0, 1) or ignored.stdout:
        raise ScanError("Index contains ignored files or ignore check failed")


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
    reject_ignored(root, paths)
    for path in paths:
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ScanError("Unsafe index path")
        if not (root / relative).resolve().is_relative_to(root.resolve()):
            raise ScanError("Tracked path escapes repository")
        if not stat.S_ISREG((root / relative).lstat().st_mode):
            raise ScanError("Only tracked regular files are supported")
    return paths


def snapshot_index(root: Path, paths: list[str], destination: Path) -> None:
    """Copy staged blobs, never checkout filters or mutable working-tree contents."""
    executable = shutil.which("git")
    if executable is None:
        raise ScanError("Git executable is unavailable")
    completed = subprocess.run(  # nosec B603
        [executable, "ls-files", "--stage", "-z"],
        cwd=root, capture_output=True, check=True, timeout=15,
    )
    entries = {}
    for record in completed.stdout.decode("utf-8").split("\0"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode, oid, stage = metadata.split()
        if (
            mode not in {"100644", "100755"}
            or stage != "0"
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid)
            or not oid.strip("0")
            or path in entries
        ):
            raise ScanError("Unsupported index entry")
        entries[path] = oid
    if set(entries) != set(paths):
        raise ScanError("Index changed during enumeration")
    for path in paths:
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ScanError("Unsafe index path")
        blob = subprocess.run(  # nosec B603
            [executable, "cat-file", "blob", entries[path]],
            cwd=root, capture_output=True, check=True, timeout=15,
        )
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # The private temporary parent prevents access while these files exist.
        with target.open("xb") as stream:
            stream.write(blob.stdout)
    reject_ignored(root, paths, destination)


def scan(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    """The detector's scan command exits zero on findings; enforce failure here."""
    paths = tracked_files(root)
    with TemporaryDirectory(prefix="hardcheck-staged-secrets-") as directory:
        snapshot = Path(directory)
        snapshot_index(root, paths, snapshot)
        # No verification or Git checkout filters: staged candidates stay local.
        completed = subprocess.run(  # nosec B603
            [
                sys.executable, "-m", "detect_secrets", "scan", "--no-verify",
                "--all-files", "--", *("./" + path for path in paths),
            ],
            cwd=snapshot, capture_output=True, check=False, timeout=120,
        )
    if completed.returncode or completed.stderr:
        raise ScanError("Secret detector did not complete cleanly")
    document = json.loads(completed.stdout)
    if not isinstance(document, dict) or not isinstance(document.get("results"), dict):
        raise ScanError("Invalid detector response")
    findings = []
    for path, items in document["results"].items():
        relative = Path(path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or str(relative) not in paths
        ):
            raise ScanError("Detector returned an unscanned path")
        if not isinstance(items, list):
            raise ScanError("Invalid detector findings")
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
    print(f"Secret scan: {count} staged files; no findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
