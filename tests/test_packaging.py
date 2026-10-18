"""Build distributions offline and verify the source archive is self-contained."""

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def test_source_archive_contains_tools_tests_and_report_resources(tmp_path):
    repository = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    source.mkdir()
    for name in (
        ".editorconfig", ".gitignore", ".github", "LICENSE", "README.md",
        "README.tr.md", "pyproject.toml", "MANIFEST.in", "docs", "examples",
        "scripts", "src", "tests",
    ):
        origin = repository / name
        target = source / name
        if origin.is_dir():
            shutil.copytree(
                origin, target,
                ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", ".DS_Store"),
            )
        else:
            shutil.copy2(origin, target)
    for name in (".env", ".venv/local.py", "scan-output/report.html"):
        target = source / name
        target.parent.mkdir(exist_ok=True)
        target.write_text("private synthetic packaging fixture\n")
    dist = tmp_path / "dist"
    build = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)],
        cwd=source, capture_output=True, text=True, timeout=90,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    assert "project.license` as a TOML table is deprecated" not in build.stderr
    with tarfile.open(next(dist.glob("*.tar.gz"))) as archive:
        members = archive.getmembers()
        top = Path(members[0].name).parts[0]
        names = {
            str(Path(member.name).relative_to(top))
            for member in members if member.isfile()
        }
        expected = {
            ".gitignore", "LICENSE", "MANIFEST.in", "pyproject.toml",
            "README.md", "README.tr.md", "examples/policy.yaml",
            "scripts/check_secrets.py", "scripts/audit_dependencies.py",
            "scripts/validate_install.py",
            "scripts/validate_html_layout.py",
            "docs/CONTRIBUTING.md", "docs/SECURITY.md", "docs/RELEASING.md",
        }
        expected.update(
            str(path.relative_to(source))
            for path in (source / "tests").rglob("*.py")
        )
        assert expected <= names
        assert not names.intersection(
            {".env", ".venv/local.py", "scan-output/report.html"}
        )
        extracted = tmp_path / "extracted"
        for member in members:
            if not member.isfile():
                continue
            relative = Path(member.name).relative_to(top)
            assert not relative.is_absolute() and ".." not in relative.parts
            target = extracted / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream:
                target.write_bytes(stream.read())
    imported = subprocess.run(
        [sys.executable, "-c", "from scripts import check_secrets, audit_dependencies"],
        cwd=extracted, capture_output=True, text=True, timeout=15,
    )
    assert imported.returncode == 0, imported.stderr
    with zipfile.ZipFile(next(dist.glob("*.whl"))) as archive:
        names = set(archive.namelist())
        assert {
            "hardcheck/i18n/en.yaml", "hardcheck/i18n/tr.yaml",
            "hardcheck/reports/templates/report.html.j2",
            "hardcheck/reports/templates/report.css",
        } <= names
        metadata = next(name for name in names if name.endswith(".dist-info/METADATA"))
        assert "License-Expression: MIT" in archive.read(metadata).decode()
        assert any(name.endswith(".dist-info/licenses/LICENSE") for name in names)
