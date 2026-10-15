# HardCheck

Read-only Linux security auditing CLI, implemented in Python 3.11+.

## Current status

The first two milestones are implemented: four SSH checks, a check registry and
isolated scan engine, strict YAML scan policies, bounded global SSH Include
processing, and automated tests on Python 3.11 and 3.12.

JSON/HTML reporting, translated output, scoring and other check families are
planned; they are not available in this release. Unsupported output options
return exit code 2 rather than silently ignoring the request.

## Install and run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m hardcheck --version
python -m hardcheck list-checks
python -m hardcheck scan
python -m hardcheck scan --config examples/policy.yaml --min-severity high
```

Use an ordinary account. Inaccessible configuration produces an explicit uncertain
result; do not elevate privileges merely to turn warnings into passes.

## Checks

| ID | Explicit policy |
| --- | --- |
| SSH-001 | PermitRootLogin no |
| SSH-002 | PasswordAuthentication no |
| SSH-003 | MaxAuthTries between 1 and 4 |
| SSH-004 | PermitEmptyPasswords no |

A static PASS does not prove the running daemon uses the inspected configuration.
Match blocks and unsupported or unreadable configuration produce WARN. See
[configuration and limits](docs/day-02.md) before interpreting results.

Exit codes: 0 means no displayed FAIL and no internal ERROR; 1 means a displayed
FAIL; 2 means invalid/unsupported input or an internal ERROR. WARN and SKIP are
not compliance evidence. Severity filtering affects displayed findings and FAIL
exit status; internal ERROR always returns 2, even if filtered from display.

## Development

```sh
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
```

Tests use temporary files and injected failures rather than changing host settings.
Never commit environments, private keys, credentials or local audit data.
The project is under active development; its current scope is not a complete
system security assessment. License: MIT.
