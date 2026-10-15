"""TCP tables are synthetic, including IPv6 and incomplete observations."""

import pytest

from hardcheck.checks.listeners import LegacyListenerCheck
from hardcheck.models import Status

HEADER = "  sl local_address rem_address st tx_queue rx_queue\n"


def row(port, width=8, state="0A"):
    return f"0: {'0' * width}:{port:04X} {'0' * width}:0000 {state} 0 0 0 0 0 0\n"


@pytest.mark.parametrize(
    ("port", "state", "expected"),
    [
        (22, "0A", Status.PASS),
        (21, "0A", Status.FAIL),
        (23, "0A", Status.FAIL),
        (23, "01", Status.PASS),
    ],
)
@pytest.mark.parametrize("family", ["tcp", "tcp6"])
def test_listeners(tmp_path, family, port, state, expected):
    for name in ("tcp", "tcp6"):
        (tmp_path / name).write_text(HEADER)
    (tmp_path / family).write_text(
        HEADER + row(port, 8 if family == "tcp" else 32, state)
    )
    assert LegacyListenerCheck(tmp_path).run().status == expected


def test_partial_and_malformed_tables(tmp_path):
    assert LegacyListenerCheck(tmp_path).run().status == Status.SKIP
    (tmp_path / "tcp").write_text(HEADER + row(21))
    assert LegacyListenerCheck(tmp_path).run().status == Status.FAIL
    (tmp_path / "tcp").write_text(HEADER + "malformed\n")
    assert LegacyListenerCheck(tmp_path).run().status == Status.WARN
    (tmp_path / "tcp").write_text(HEADER)
    assert LegacyListenerCheck(tmp_path).run().status == Status.SKIP
