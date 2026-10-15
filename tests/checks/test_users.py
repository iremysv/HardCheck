"""User checks run only against temporary account databases."""

import pytest

from hardcheck.checks.users import EmptyPasswordCheck, RootUidCheck
from hardcheck.models import Status


@pytest.mark.parametrize(("password", "expected"), [
    ("", Status.FAIL), ("!", Status.PASS), ("!!", Status.PASS),
    ("*", Status.PASS), ("$fixture$hash", Status.PASS),
])
def test_empty_password_fields(tmp_path, password, expected):
    path = tmp_path / "shadow"
    path.write_text(f"private-user:{password}:20000:0:90:7:::\n")
    result = EmptyPasswordCheck(path).run()
    assert result.status == expected
    assert "private-user" not in repr(result)
    assert "$fixture" not in repr(result)


@pytest.mark.parametrize(("content", "expected"), [
    ("root:x:0:0::/root:/bin/sh\nuser:x:1000:1000::/:/bin/sh\n", Status.PASS),
    ("root:x:0:0::/root:/bin/sh\nother:x:0:0::/:/bin/sh\n", Status.FAIL),
    ("root:x:1:0::/root:/bin/sh\n", Status.FAIL),
    ("other:x:0:0::/:/bin/sh\n", Status.FAIL),
    ("root:x:0_0:0::/:/bin/sh\n", Status.WARN),
    ("root:x:0:bad::/:/bin/sh\n", Status.WARN),
    ("root:x:0:0::/:/bin/sh\nroot:x:0:0::/:/bin/sh\n", Status.WARN),
    ("+nis:x:0:0::/:/bin/sh\n", Status.WARN),
    ("root:x:0:9999999999::/:/bin/sh\n", Status.WARN),
    ("malformed", Status.WARN), ("", Status.WARN),
])
def test_root_uid(tmp_path, content, expected):
    path = tmp_path / "passwd"
    path.write_text(content)
    assert RootUidCheck(path).run().status == expected


@pytest.mark.parametrize("check", [EmptyPasswordCheck, RootUidCheck])
def test_account_read_failures(tmp_path, monkeypatch, check):
    import hardcheck.checks.users as users

    assert check(tmp_path / "missing").run().status == Status.SKIP

    def denied(*args):
        raise PermissionError

    monkeypatch.setattr(users, "read_regular_text", denied)
    assert check(tmp_path / "private").run().status == Status.WARN
