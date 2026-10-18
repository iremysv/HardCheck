"""Offline acceptance checks for an installed artifact using only synthetic probes.

Run with a fresh virtual environment's Python, without PYTHONPATH. Optional
--reports exports synthetic HTML examples to a new private directory.
"""

import argparse
import contextlib
import io
import json
import os
import stat
import subprocess  # nosec B404
import sys
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


class ValidationError(ValueError):
    """An installed artifact failed an acceptance requirement."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate(reports: Path | None = None) -> None:
    import hardcheck
    from hardcheck import cli
    from hardcheck.environment import Environment
    from hardcheck.models import Severity, Status
    from hardcheck.registry import get_registered_checks

    require(
        sys.prefix != sys.base_prefix
        and Path(hardcheck.__file__)
        .resolve()
        .is_relative_to(Path(sys.prefix).resolve()),
        "Use an installed artifact in a virtual environment without PYTHONPATH.",
    )
    checks = get_registered_checks()
    require(len(checks) == 18, "Expected eighteen built-in controls.")
    environment = Environment("Linux", "fixture", "systemd", True)
    findings = [
        replace(
            check.result(check, list(Status)[index % len(Status)]),
            environment=environment,
        )
        for index, check in enumerate(checks)
    ]

    def invoke(arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        return code, out.getvalue(), err.getvalue()

    child_environment = {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    with TemporaryDirectory(prefix="hardcheck-installed-validation-") as directory:
        root = Path(directory)
        binary = Path(sys.executable).parent / "hardcheck"
        for option in ("--version", "--help", "list-checks"):
            # Fixed installed entry point and fixed read-only arguments; no shell.
            result = subprocess.run(  # nosec B603
                [str(binary), option],
                cwd=root,
                env=child_environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            require(result.returncode == 0, "Installed entry point failed.")
            if option == "--version":
                require(
                    result.stdout.strip() == hardcheck.__version__, "Version mismatch."
                )
            elif option == "list-checks":
                require(
                    result.stdout.splitlines() == [check.check_id for check in checks],
                    "Installed registry differs from the entry point.",
                )
        if reports is not None:
            reports.mkdir(mode=0o700)
        for language in ("en", "tr"):
            for format in ("terminal", "json", "html"):
                args = ["scan", "--lang", language, "--format", format, "--explain"]
                with patch.object(cli, "run_checks", return_value=findings):
                    code, output, error = invoke(args)
                    require(code == 2 and not error, "Mixed-result report failed.")
                    require(
                        all(check.check_id in output for check in checks),
                        "A built-in control is missing from its report.",
                    )
                    if format == "json":
                        data = json.loads(output)
                        require(data["language"] == language, "Wrong JSON language.")
                        require(len(data["findings"]) == 18, "Incomplete JSON report.")
                        require(
                            data["scope"]["environments"][0]["distribution"]
                            == "fixture",
                            "JSON environment was lost.",
                        )
                    if format == "html":
                        require(
                            f'<html lang="{language}">' in output,
                            "Wrong HTML language.",
                        )
                        require(
                            "<script" not in output, "Unexpected active HTML content."
                        )
                    target = reports if reports and format == "html" else root
                    path = target / f"report-{language}.{format}"
                    require(
                        invoke([*args, "--output", str(path)]) == (2, "", ""),
                        "Private report export failed.",
                    )
                    require(
                        path.read_text(encoding="utf-8") == output, "Export differs."
                    )
                    require(
                        stat.S_IMODE(path.stat().st_mode) == 0o600,
                        "Unsafe report mode.",
                    )
                    require(
                        bool(invoke([*args, "--output", str(path)])[2]),
                        "Overwrite allowed.",
                    )
                    require(
                        path.read_text(encoding="utf-8") == output,
                        "Existing file changed.",
                    )
                hidden = [replace(item, severity=Severity.LOW) for item in findings]
                with patch.object(cli, "run_checks", return_value=hidden):
                    code, output, error = invoke([*args, "--min-severity", "critical"])
                    require(code == 2 and not error, "A filtered error was hidden.")
                    if format == "json":
                        data = json.loads(output)
                        require(
                            data["findings"] == [], "Filtered selection is not empty."
                        )
                        require(
                            data["summary"]["score_percent"] is None,
                            "Fabricated score.",
                        )
                    if reports is not None and format == "html":
                        require(
                            invoke(
                                [
                                    *args,
                                    "--min-severity",
                                    "critical",
                                    "--output",
                                    str(reports / f"empty-{language}.html"),
                                ]
                            )
                            == (2, "", ""),
                            "Empty HTML export failed.",
                        )
                for status in Status:
                    sample = [replace(findings[0], status=status)]
                    expected = (
                        2
                        if status == Status.ERROR
                        else 1
                        if status == Status.FAIL
                        else 0
                    )
                    with patch.object(cli, "run_checks", return_value=sample):
                        require(
                            invoke(args)[0] == expected, "Incorrect status exit code."
                        )
        policy = root / "policy.yaml"
        policy.write_text(
            "version: 1\nchecks:\n"
            + "".join(
                f"  {check.check_id}: {{enabled: false, severity: low}}\n"
                for check in checks
            ),
            encoding="utf-8",
        )
        # Disabled checks on an injected Linux environment never probe the host.
        with patch("hardcheck.engine.detect_environment", return_value=environment):
            code, output, error = invoke(
                [
                    "scan",
                    "--config",
                    str(policy),
                    "--format",
                    "json",
                ]
            )
        require(code == 0 and not error, "Disabled policy failed.")
        data = json.loads(output)
        require(
            data["summary"]["counts"]["SKIP"] == 18,
            "Policy did not disable all probes.",
        )
        require(
            all(
                item["reason"] == "disabled_by_policy" and item["severity"] == "low"
                for item in data["findings"]
            ),
            "Policy reason or severity was lost.",
        )
        # Fixed module invocation checks this environment, with no package installation.
        result = subprocess.run(  # nosec B603
            [sys.executable, "-m", "pip", "check"],
            cwd=root,
            env=child_environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        require(result.returncode == 0, "Installed dependencies are inconsistent.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports", type=Path, help="Export synthetic HTML to a NEW directory"
    )
    arguments = parser.parse_args()
    try:
        validate(arguments.reports)
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ImportError, OSError, ValueError, subprocess.SubprocessError):
        print("Installed artifact validation could not complete.", file=sys.stderr)
        return 2
    print(
        "Installed artifact validation passed: "
        "18 controls, en/tr, reports, exits and policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
