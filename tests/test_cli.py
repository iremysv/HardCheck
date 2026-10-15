"""Tests for the command-line argument parser."""

from hardcheck.cli import build_parser


def test_scan_defaults():
    """Verify the default scan options."""
    args = build_parser().parse_args(["scan"])
    assert args.format == "terminal"
    assert args.lang == "en"
