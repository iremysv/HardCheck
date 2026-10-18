"""File readers reject blocking/special inputs and enforce byte-based limits."""

import os

import pytest

from hardcheck.safe_io import read_regular_text


def test_byte_limit_includes_multibyte_characters(tmp_path):
    path = tmp_path / "fixture"
    path.write_text("ö", encoding="utf-8")
    assert read_regular_text(path, 2) == "ö"
    with pytest.raises(ValueError, match="size limit"):
        read_regular_text(path, 1)
    assert path.read_text(encoding="utf-8") == "ö"


def test_invalid_utf8_is_not_replaced_or_accepted(tmp_path):
    path = tmp_path / "fixture"
    path.write_bytes(b"\xff")
    with pytest.raises(UnicodeError):
        read_regular_text(path)


def test_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular file"):
        read_regular_text(path)


def test_directories_are_rejected(tmp_path):
    with pytest.raises((IsADirectoryError, ValueError)):
        read_regular_text(tmp_path)


def test_large_regular_file_is_not_truncated_into_success(tmp_path):
    path = tmp_path / "fixture"
    path.write_bytes(b"x" * 4097)
    with pytest.raises(ValueError, match="size limit"):
        read_regular_text(path, 4096)
