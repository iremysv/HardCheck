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


@pytest.mark.parametrize("format", ["terminal", "json"])
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
    assert cli.main(["scan", "--format", "html"]) == 2
    captured = capsys.readouterr()
    assert captured.err
    assert not captured.out
