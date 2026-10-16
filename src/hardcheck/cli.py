"""Command-line interface for HardCheck."""

import argparse
import os
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from hardcheck import __version__
from hardcheck.config import ConfigError, load_policy
from hardcheck.engine import run_checks
from hardcheck.models import Severity, Status
from hardcheck.registry import get_registered_checks
from hardcheck.reporting import json_report, terminal_summary
from hardcheck.scoring import exit_code


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
    if arguments.format == "html" or arguments.lang != "en":
        print("This option is not available in the initial release.", file=sys.stderr)
        return 2
    if arguments.output == "":
        print("Output path must not be empty.", file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(arguments.config)) if arguments.config else None
    except ConfigError as exc:
        print(f"Invalid configuration: {exc}", file=sys.stderr)
        return 2
    results = run_checks(policy)
    all_results = results
    has_errors = any(result.status == Status.ERROR for result in results)
    if arguments.min_severity:
        priorities = list(Severity)
        minimum = priorities.index(Severity(arguments.min_severity))
        results = [r for r in results if priorities.index(r.severity) >= minimum]
    if arguments.format == "json":
        report = json_report(results, all_results, arguments.min_severity)
    else:
        buffer = StringIO()
        with redirect_stdout(buffer):
            print_terminal(results, all_results, arguments.explain)
        report = buffer.getvalue()
    try:
        if arguments.output is None:
            print(report, end="")
        else:
            descriptor = os.open(
                arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(report)
    except OSError:
        print("Could not write report; choose a new writable path.", file=sys.stderr)
        return 2
    return 2 if has_errors else exit_code(results)


def print_terminal(results, all_results, explain: bool) -> None:
    """Print findings and the displayed assessment scope."""
    for result in results:
        detail = f" — {result.detail}" if result.detail else ""
        print(f"{result.check_id}: {result.status.value}{detail}")
        if explain:
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
    print(terminal_summary(results))
    if len(results) != len(all_results):
        print(
            f"Hidden controls: {len(all_results) - len(results)}; "
            f"scan ERROR={sum(r.status == Status.ERROR for r in all_results)}"
        )
