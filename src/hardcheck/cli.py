"""Command-line interface for HardCheck."""

import argparse
import os
import sys
from pathlib import Path

from jinja2 import TemplateError

from hardcheck import __version__
from hardcheck.config import ConfigError, load_policy
from hardcheck.engine import run_checks
from hardcheck.localization import translate
from hardcheck.models import Severity, Status
from hardcheck.registry import get_registered_checks
from hardcheck.reporting import json_report, terminal_report
from hardcheck.reports.html import html_report
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
    scan.add_argument(
        "--output", help="Create a private report file; existing paths are rejected"
    )
    scan.add_argument(
        "--lang",
        choices=("en", "tr"),
        default="en",
        help="Report and diagnostic language (default: en)",
    )
    scan.add_argument("--config")
    scan.add_argument(
        "--explain",
        action="store_true",
        help="Show safe evidence and manual remediation guidance",
    )
    scan.add_argument("--min-severity", choices=("low", "medium", "high", "critical"))
    serve = commands.add_parser("serve", help="Open the local read-only panel")
    serve.add_argument("--open-browser", action="store_true")
    serve.add_argument("--port", type=int, default=8765)
    commands.add_parser("install-launcher", help="Install the user Linux launcher")
    commands.add_parser("uninstall-launcher", help="Remove the user Linux launcher")
    commands.add_parser("list-checks", help="Show available check identifiers")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute a CLI command and return the appropriate exit code."""
    arguments = build_parser().parse_args(argv)
    if arguments.command in ("install-launcher", "uninstall-launcher"):
        from hardcheck.desktop import install_launcher

        return install_launcher(remove=arguments.command == "uninstall-launcher")
    if arguments.command == "serve":
        if not 1024 <= arguments.port <= 65535:
            print("Port must be between 1024 and 65535", file=sys.stderr)
            return 2
        from hardcheck.launcher import serve

        return serve(arguments.port, arguments.open_browser)
    if arguments.command == "list-checks":
        for check_class in get_registered_checks():
            print(check_class.check_id)
        return 0
    if arguments.output == "":
        print(translate("output_empty", arguments.lang), file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(arguments.config)) if arguments.config else None
    except ConfigError:
        print(translate("invalid_config", arguments.lang), file=sys.stderr)
        return 2
    results = run_checks(policy)
    all_results = results
    has_errors = any(result.status == Status.ERROR for result in results)
    if arguments.min_severity:
        priorities = list(Severity)
        minimum = priorities.index(Severity(arguments.min_severity))
        results = [r for r in results if priorities.index(r.severity) >= minimum]
    try:
        if arguments.format == "json":
            report = json_report(
                results, all_results, arguments.min_severity, arguments.lang
            )
        elif arguments.format == "html":
            report = html_report(
                results, all_results, arguments.min_severity, arguments.lang
            )
        else:
            report = terminal_report(
                results, all_results, arguments.explain, arguments.lang
            )
    except (OSError, TemplateError, ValueError):
        print(translate("render_error", arguments.lang), file=sys.stderr)
        return 2
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
        print(translate("write_error", arguments.lang), file=sys.stderr)
        return 2
    return 2 if has_errors else exit_code(results)
