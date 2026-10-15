"""Command-line interface for HardCheck."""

import argparse
import sys
from pathlib import Path

from hardcheck import __version__
from hardcheck.config import ConfigError, load_policy
from hardcheck.engine import run_checks
from hardcheck.models import Severity, Status
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
    scan.add_argument(
        "--explain",
        action="store_true",
        help="Show safe evidence and manual remediation guidance",
    )
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
    if (
        arguments.format != "terminal"
        or arguments.output is not None
        or arguments.lang != "en"
    ):
        print("This option is not available in the initial release.", file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(arguments.config)) if arguments.config else None
    except ConfigError as exc:
        print(f"Invalid configuration: {exc}", file=sys.stderr)
        return 2
    results = run_checks(policy)
    has_errors = any(result.status == Status.ERROR for result in results)
    if arguments.min_severity:
        priorities = list(Severity)
        minimum = priorities.index(Severity(arguments.min_severity))
        results = [r for r in results if priorities.index(r.severity) >= minimum]
    for result in results:
        detail = f" — {result.detail}" if result.detail else ""
        print(f"{result.check_id}: {result.status.value}{detail}")
        if arguments.explain:
            print(f"  Title: {result.title}")
            print(f"  Expected: {result.expected}")
            facts = []
            for fact in result.evidence:
                value = fact.value
                if fact.key == "mode_bits" and type(value) is int:
                    display = f"{value:04o}"
                else:
                    display = str(value)
                facts.append(f"{fact.key.value}={display}")
            print(f"  Observed: {'; '.join(facts)}")
            print(f"  Rationale: {result.rationale}")
            print(f"  Manual remediation: {result.remediation}")
            print(f"  Reference: {result.reference}")
    if has_errors:
        return 2
    return 1 if any(result.status == Status.FAIL for result in results) else 0
