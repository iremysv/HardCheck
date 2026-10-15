"""Command-line interface for HardCheck."""

import argparse

from hardcheck import __version__
from hardcheck.engine import run_checks
from hardcheck.models import Status
from hardcheck.registry import get_registered_checks


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="hardcheck")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Run security checks")
    scan.add_argument(
        "--format",
        choices=("terminal", "json", "html"),
        default="terminal",
    )
    scan.add_argument("--output")
    scan.add_argument("--lang", choices=("en", "tr"), default="en")
    scan.add_argument("--config")
    scan.add_argument("--min-severity", choices=("low", "medium", "high", "critical"))
    commands.add_parser("list-checks", help="Show available check identifiers")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute a CLI command and return the appropriate exit code."""
    arguments = build_parser().parse_args(argv)
    if arguments.command == "list-checks":
        for check_class in get_registered_checks():
            print(check_class.check_id)
        return 0
    if arguments.format != "terminal" or arguments.output or arguments.config:
        print("This option is not available in the initial release.")
        return 2
    results = run_checks()
    for result in results:
        print(f"{result.check_id}: {result.status.value}")
    return 1 if any(result.status == Status.FAIL for result in results) else 0
