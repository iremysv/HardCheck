"""Report contracts, filtering, privacy and CLI exit behavior."""

import json
from dataclasses import replace

import pytest

from hardcheck import cli
from hardcheck.models import Severity, Status
from hardcheck.registry import get_registered_checks


def fake_result(status, severity=Severity.HIGH):
    check = get_registered_checks()[0]
    return replace(
        check.result(check, status),
        severity=severity,
        detail="private-token-from-probe",
    )


def test_json_contract_and_no_raw_detail(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_checks", lambda _: [fake_result(Status.PASS)])
    assert cli.main(["scan", "--format", "json"]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["schema_version"] == 1
    assert report["summary"]["score_percent"] == 100
    assert report["summary"]["coverage_percent"] == 100
    assert report["findings"][0]["status"] == "PASS"
    assert "private-token" not in output


@pytest.mark.parametrize("format", ["terminal", "json", "html"])
def test_hidden_error_still_returns_two(format, monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "run_checks",
        lambda _: [fake_result(Status.PASS), fake_result(Status.ERROR, Severity.LOW)],
    )
    assert cli.main(["scan", "--format", format, "--min-severity", "high"]) == 2
    output = capsys.readouterr().out
    if format == "json":
        report = json.loads(output)
        assert report["scope"]["hidden_controls"] == 1
        assert report["scan_summary"]["counts"]["ERROR"] == 1
        assert report["summary"]["counts"]["ERROR"] == 0
    elif format == "html":
        assert "scan ERROR=1" in output
    else:
        assert "scan ERROR=1" in output


def test_empty_filtered_selection_is_not_perfect(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "run_checks", lambda _: [fake_result(Status.FAIL, Severity.LOW)]
    )
    assert cli.main(["scan", "--format", "json", "--min-severity", "critical"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["summary"]["score_percent"] is None
    assert report["summary"]["coverage_percent"] is None
    assert report["scan_summary"]["counts"]["FAIL"] == 1


def test_invalid_input_is_stderr_only(capsys):
    assert cli.main(["scan", "--output", ""]) == 2
    captured = capsys.readouterr()
    assert captured.err
    assert not captured.out


@pytest.mark.parametrize("format", ["terminal", "json", "html"])
def test_output_is_private_and_never_overwrites(format, tmp_path, monkeypatch, capsys):
    import os
    import stat

    monkeypatch.setattr(cli, "run_checks", lambda _: [fake_result(Status.FAIL)])
    path = tmp_path / "report"
    args = ["scan", "--format", format, "--output", str(path)]
    assert cli.main(args) == 1
    assert capsys.readouterr().out == ""
    original = path.read_text()
    if format == "json":
        assert json.loads(original)["summary"]["counts"]["FAIL"] == 1
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cli.main(args) == 2
    assert path.read_text() == original
    assert capsys.readouterr().err


def test_output_does_not_follow_symlinks(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_checks", lambda _: [])
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert cli.main(["scan", "--output", str(link)]) == 2
    assert target.read_text() == "keep"
    assert cli.main(["scan", "--output", str(tmp_path / "missing" / "report")]) == 2
    assert capsys.readouterr().err


def test_shared_report_contract_preserves_json_and_input():
    from hardcheck.reporting import json_report, report_data

    selected = [fake_result(Status.WARN)]
    collected = selected + [fake_result(Status.FAIL, Severity.LOW)]
    before = tuple(collected)
    data = report_data(selected, collected, "high")
    assert data == json.loads(json_report(selected, collected, "high"))
    assert data["scope"]["hidden_controls"] == 1
    assert data["summary"]["score_percent"] is None
    assert data["scan_summary"]["score_percent"] == 0
    assert tuple(collected) == before
    assert "detail" not in data["findings"][0]
