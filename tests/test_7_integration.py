"""Report formats and languages preserve scan semantics and private file behavior."""

import json
from dataclasses import replace

import pytest
from jinja2 import TemplateNotFound

from hardcheck import cli
from hardcheck.models import Severity, Status
from hardcheck.registry import get_registered_checks


@pytest.fixture
def findings():
    check = get_registered_checks()[0]
    return [
        replace(check.result(check, status), check_id=f"TEST-{status.value}")
        for status in Status
    ]


@pytest.mark.parametrize("language", ["en", "tr"])
@pytest.mark.parametrize("format", ["terminal", "json", "html"])
@pytest.mark.parametrize("status", list(Status))
def test_formats_and_languages_preserve_exit_codes(
    language, format, status, findings, monkeypatch, capsys
):
    selected = [r for r in findings if r.status == status]
    monkeypatch.setattr(cli, "run_checks", lambda _: selected)
    expected = 2 if status == Status.ERROR else 1 if status == Status.FAIL else 0
    assert cli.main(["scan", "--lang", language, "--format", format]) == expected
    captured = capsys.readouterr()
    assert not captured.err
    assert selected[0].check_id in captured.out
    if format == "json":
        data = json.loads(captured.out)
        assert data["findings"][0]["status"] == status.value
        assert data["language"] == language


@pytest.mark.parametrize("language", ["en", "tr"])
@pytest.mark.parametrize("format", ["terminal", "json", "html"])
def test_filtered_hidden_error_and_empty_selection(
    language, format, findings, monkeypatch, capsys
):
    hidden = [replace(r, severity=Severity.LOW) for r in findings]
    monkeypatch.setattr(cli, "run_checks", lambda _: hidden)
    assert (
        cli.main(
            [
                "scan",
                "--lang",
                language,
                "--format",
                format,
                "--min-severity",
                "critical",
            ]
        )
        == 2
    )
    output = capsys.readouterr().out
    assert "TEST-ERROR" not in output
    if format == "json":
        data = json.loads(output)
        assert data["summary"]["score_percent"] is None
        assert data["summary"]["coverage_percent"] is None
        assert data["scan_summary"]["counts"]["ERROR"] == 1
    else:
        assert "ERROR=1" in output


@pytest.mark.parametrize("language", ["en", "tr"])
@pytest.mark.parametrize("format", ["terminal", "json", "html"])
def test_localized_file_matches_stdout(
    language, format, tmp_path, findings, monkeypatch, capsys
):
    monkeypatch.setattr(cli, "run_checks", lambda _: findings)
    args = ["scan", "--lang", language, "--format", format, "--explain"]
    assert cli.main(args) == 2
    expected = capsys.readouterr().out
    path = tmp_path / f"report.{format}"
    assert cli.main([*args, "--output", str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert path.read_text(encoding="utf-8") == expected
    assert cli.main([*args, "--output", str(path)]) == 2
    assert capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == expected


def test_render_failure_is_stderr_only_and_creates_no_file(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(cli, "run_checks", lambda _: [])

    def fail(*args):
        raise TemplateNotFound("private-internal-template-path")

    monkeypatch.setattr(cli, "html_report", fail)
    path = tmp_path / "report.html"
    assert (
        cli.main(["scan", "--format", "html", "--lang", "tr", "--output", str(path)])
        == 2
    )
    captured = capsys.readouterr()
    assert not captured.out
    assert "Rapor oluşturulamadı" in captured.err
    assert "private-internal" not in captured.err
    assert not path.exists()


@pytest.mark.parametrize("language", ["en", "tr"])
@pytest.mark.parametrize("format", ["terminal", "json", "html"])
def test_disabled_policy_reaches_reports_without_constructing_probes(
    language, format, tmp_path, monkeypatch, capsys
):
    checks = get_registered_checks()

    def forbidden(self):
        raise AssertionError("Disabled probes must never be constructed")

    for check in checks:
        monkeypatch.setattr(check, "__init__", forbidden)
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nchecks:\n"
        + "".join(f"  {check.check_id}: {{enabled: false}}\n" for check in checks)
    )
    assert (
        cli.main(
            ["scan", "--config", str(path), "--lang", language, "--format", format]
        )
        == 0
    )
    output = capsys.readouterr().out
    if format == "json":
        report = json.loads(output)
        assert report["summary"]["counts"]["SKIP"] == 18
        assert report["summary"]["coverage_percent"] == 0
        assert report["summary"]["score_percent"] is None
    else:
        assert "SKIP" in output
        assert ("Hesaplanamadı" if language == "tr" else "N/A") in output


def test_non_linux_report_keeps_all_controls_uncertain(monkeypatch, capsys):
    from hardcheck import engine
    from hardcheck.environment import Environment

    monkeypatch.setattr(engine, "detect_environment", lambda: Environment("Darwin"))

    def forbidden(self):
        raise AssertionError("Non-Linux probes must not be constructed")

    for check in get_registered_checks():
        monkeypatch.setattr(check, "__init__", forbidden)
    assert cli.main(["scan", "--lang", "tr", "--explain"]) == 0
    output = capsys.readouterr().out
    assert "Bu kontrol Linux gerektirir" in output
    assert "SKIP=18" in output
    assert "Hesaplanamadı" in output
