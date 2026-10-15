"""Password policy boundary and precedence tests on temporary files."""

import pytest

from hardcheck.checks.password_policy import PasswordAgeCheck, PasswordLengthCheck
from hardcheck.models import Status


@pytest.mark.parametrize(("text", "status"), [
    ("PASS_MAX_DAYS 90", Status.PASS), ("PASS_MAX_DAYS 1", Status.PASS),
    ("PASS_MAX_DAYS 91", Status.FAIL), ("PASS_MAX_DAYS 0", Status.FAIL),
    ("PASS_MAX_DAYS -1", Status.FAIL), ("PASS_MAX_DAYS 9_0", Status.WARN),
    ("PASS_MAX_DAYS 90 extra", Status.WARN), ("# defaults", Status.WARN),
    ("PASS_MAX_DAYS 90\nPASS_MAX_DAYS 365", Status.WARN),
])
def test_age_policy(tmp_path, text, status):
    path = tmp_path / "login.defs"
    path.write_text(text)
    result = PasswordAgeCheck(path).run()
    assert result.status == status
    if status in (Status.PASS, Status.FAIL):
        assert "existing accounts excluded" in result.detail


@pytest.mark.parametrize(("text", "status"), [
    ("minlen = 12", Status.PASS), ("minlen = 11", Status.FAIL),
    ("minlen = 12\ndcredit = 1", Status.FAIL),
    ("minlen = 13\ndcredit = 1", Status.PASS),
    ("minlen = 12\ndcredit = -1", Status.PASS),
    ("minlen = 20\nenforcing = 0", Status.FAIL),
    ("minlen = 1_2", Status.WARN), ("minlen 12", Status.WARN),
    ("# missing", Status.WARN), ("minlen = 20\nminlen = 8", Status.FAIL),
])
def test_length_policy(tmp_path, text, status):
    path = tmp_path / "pwquality.conf"
    path.write_text(text)
    assert PasswordLengthCheck(path).run().status == status


def test_dropin_precedence(tmp_path):
    path = tmp_path / "pwquality.conf"
    directory = tmp_path / "pwquality.conf.d"
    directory.mkdir()
    (directory / "10.conf").write_text("minlen = 8")
    (directory / "20.conf").write_text("minlen = 14")
    path.write_text("# use snippets")
    assert PasswordLengthCheck(path).run().status == Status.PASS
    path.write_text("minlen = 9")
    assert PasswordLengthCheck(path).run().status == Status.FAIL


def test_password_policy_read_errors(tmp_path, monkeypatch):
    import hardcheck.checks.password_policy as policy

    assert PasswordAgeCheck(tmp_path / "missing").run().status == Status.SKIP
    assert PasswordLengthCheck(tmp_path / "missing").run().status == Status.WARN

    def denied(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(policy, "read_regular_text", denied)
    assert PasswordAgeCheck(tmp_path / "private").run().status == Status.WARN
    assert PasswordLengthCheck(tmp_path / "private").run().status == Status.WARN
