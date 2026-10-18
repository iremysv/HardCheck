"""Security tooling must fail on findings, incomplete scans and malformed input."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import audit_dependencies, check_secrets


@pytest.fixture
def repository(tmp_path):
    git = shutil.which("git")
    assert git
    subprocess.run([git, "init", "--quiet", str(tmp_path)], check=True)
    return tmp_path


def stage(root, *paths):
    subprocess.run([shutil.which("git"), "add", "--", *paths], cwd=root, check=True)


def test_secret_scan_detects_generated_fixture_without_leaking_value(
    repository, capsys
):
    # This generated format is not an issued credential and is never verified online.
    token = (
        "AKIA" + hashlib.sha256(b"hardcheck synthetic fixture").hexdigest()[:16].upper()
    )
    (repository / "settings.txt").write_text(f'aws_access_key_id = "{token}"\n')
    stage(repository, "settings.txt")
    count, findings = check_secrets.scan(repository)
    assert count == 1 and findings
    assert any("AWS" in finding[2] for finding in findings)
    assert token not in repr(findings)
    from unittest.mock import patch

    with patch.object(check_secrets, "scan", return_value=(count, findings)):
        assert check_secrets.main() == 1
    output = capsys.readouterr().out
    assert token not in output
    assert "values withheld" in output


def test_secret_scan_ignores_untracked_local_environment(repository):
    (repository / ".gitignore").write_text(".env\n")
    (repository / "safe.py").write_text('print("fixture")\n')
    (repository / ".env").write_text("LOCAL=fixture\n")
    stage(repository, ".gitignore", "safe.py")
    count, findings = check_secrets.scan(repository)
    assert count == 2
    assert findings == []


def test_tracked_symlink_is_an_incomplete_scan(repository):
    (repository / "real.txt").write_text("fixture")
    (repository / "link.txt").symlink_to("real.txt")
    stage(repository, "link.txt")
    with pytest.raises(check_secrets.ScanError):
        check_secrets.scan(repository)


def test_tracked_file_removed_before_scan_is_not_clean(repository, monkeypatch, capsys):
    path = repository / "missing.txt"
    path.write_text("fixture")
    stage(repository, "missing.txt")
    path.unlink()
    original = check_secrets.scan
    monkeypatch.setattr(check_secrets, "scan", lambda _: original(repository))
    assert check_secrets.main() == 2
    captured = capsys.readouterr()
    assert "not clean" in captured.err
    assert not captured.out


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(returncode=1, stdout=b"", stderr=b"private tool detail"),
        SimpleNamespace(returncode=0, stdout=b'{"results": {}}', stderr=b"warning"),
        SimpleNamespace(returncode=0, stdout=b"invalid json", stderr=b""),
        SimpleNamespace(returncode=0, stdout=b"{}", stderr=b""),
    ],
)
def test_detector_errors_and_warnings_cannot_pass(response, monkeypatch):
    monkeypatch.setattr(check_secrets, "tracked_files", lambda _: ["fixture.py"])
    monkeypatch.setattr(check_secrets.subprocess, "run", lambda *a, **k: response)
    with pytest.raises((check_secrets.ScanError, ValueError)):
        check_secrets.scan(Path("."))


def test_detector_never_verifies_candidates_online(monkeypatch):
    monkeypatch.setattr(check_secrets, "tracked_files", lambda _: ["-weird.py"])

    def execute(argv, **kwargs):
        assert "--no-verify" in argv
        assert argv[-1] == "./-weird.py"
        assert "--" in argv
        assert kwargs.get("shell", False) is False
        assert kwargs["timeout"] == 120
        return SimpleNamespace(
            returncode=0, stdout=json.dumps({"results": {}}).encode(), stderr=b""
        )

    monkeypatch.setattr(check_secrets.subprocess, "run", execute)
    assert check_secrets.scan(Path(".")) == (1, [])


def distribution(name, version):
    return SimpleNamespace(metadata={"Name": name}, version=version)


def test_dependency_snapshot_is_exact_and_excludes_only_project(monkeypatch):
    monkeypatch.setattr(
        audit_dependencies.metadata,
        "distributions",
        lambda: [
            distribution("HardCheck", "0.1.0"),
            distribution("pip", "26.2.1"),
            distribution("PyYAML", "6.0.3"),
        ],
    )
    assert audit_dependencies.resolved_requirements() == [
        "pip==26.2.1",
        "pyyaml==6.0.3",
    ]


@pytest.mark.parametrize(
    "items",
    [
        [],
        [distribution("bad\n--index-url", "1.0")],
        [distribution("fixture", "invalid version")],
        [distribution("fixture", "1.0"), distribution("fixture", "2.0")],
    ],
)
def test_invalid_or_conflicting_dependency_snapshot_is_rejected(items, monkeypatch):
    monkeypatch.setattr(audit_dependencies.metadata, "distributions", lambda: items)
    with pytest.raises(ValueError):
        audit_dependencies.resolved_requirements()


def test_audit_tool_failure_is_not_success(monkeypatch):
    monkeypatch.setattr(
        audit_dependencies, "resolved_requirements", lambda: ["fixture==1"]
    )

    def execute(argv, **kwargs):
        assert "--strict" in argv and "--disable-pip" in argv and "--no-deps" in argv
        assert "--ignore-vuln" not in argv
        assert Path(argv[argv.index("--requirement") + 1]).read_text() == "fixture==1\n"
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(audit_dependencies.subprocess, "run", execute)
    assert audit_dependencies.main() == 1


def test_audit_timeout_has_sanitized_error(monkeypatch, capsys):
    monkeypatch.setattr(
        audit_dependencies, "resolved_requirements", lambda: ["fixture==1"]
    )

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("private environment detail", 1)

    monkeypatch.setattr(audit_dependencies.subprocess, "run", timeout)
    assert audit_dependencies.main() == 2
    captured = capsys.readouterr()
    assert "could not complete" in captured.err
    assert "private" not in captured.err


@pytest.mark.parametrize(
    "relative",
    [
        ".env",
        ".venv/config.txt",
        "venv/config.txt",
        "scan-output/report.html",
        "__pycache__/fixture.pyc",
    ],
)
def test_force_added_local_files_cannot_bypass_ignore_policy(repository, relative):
    ignore = Path(__file__).resolve().parents[1] / ".gitignore"
    (repository / ".gitignore").write_bytes(ignore.read_bytes())
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fixture")
    subprocess.run(
        [shutil.which("git"), "add", "-f", "--", relative, ".gitignore"],
        cwd=repository,
        check=True,
    )
    with pytest.raises(check_secrets.ScanError, match="ignored files"):
        check_secrets.tracked_files(repository)


def test_report_source_directory_remains_allowed(repository):
    ignore = Path(__file__).resolve().parents[1] / ".gitignore"
    (repository / ".gitignore").write_bytes(ignore.read_bytes())
    path = repository / "src/hardcheck/reports/template.txt"
    path.parent.mkdir(parents=True)
    path.write_text("fixture")
    stage(repository, ".gitignore", "src/hardcheck/reports/template.txt")
    assert len(check_secrets.tracked_files(repository)) == 2
