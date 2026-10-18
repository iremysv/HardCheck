# Contributing to HardCheck

HardCheck is a Python 3.11+ read-only Linux auditing CLI. Start with the
[threat model](threat-model.md), [finding contract](findings.md) and
[reporting contract](reporting.md). Development on another OS is possible with
injected fixtures; it does not validate live Linux behavior.

## Development setup

From the repository root, using an ordinary account:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2,<27'
python -m pip install -e '.[dev,security]'
python -m pip check
```

Keep virtual environments, local scan results and credentials untracked. Use
synthetic data in examples, tests and issue reports. Never include real shadow
records, private keys, account inventories or raw host configuration.

## Implementation requirements

- Preserve read-only inspection: no automatic remediation, sudo, shell execution
  or network probing. New queries need fixed arguments and bounded execution.
- Register built-in checks explicitly. YAML may override enabled/severity metadata
  only; it must never introduce executable checks, paths or commands.
- Distinguish PASS, FAIL, WARN, SKIP and ERROR. Missing visibility must not become
  PASS. Internal errors must retain exit code 2 even when presentation filters
  hide the affected result.
- Keep evidence bounded and sanitized. Add fixed evidence keys/tokens and counts
  instead of raw input, account names or private paths.
- Update canonical guidance and both English/Turkish catalogs together. Preserve
  stable machine tokens, JSON fields and cross-format score calculations.
- Document each check's scope, uncertainty and primary references. Update the
  threat model when a trust boundary changes.

Tests should use temporary fixtures and injected environments/queries. Include
meaningful failure cases for changed behavior, such as unreadable/malformed input,
partial visibility and resource limits. Do not change the developer's host settings
or require access to its real account database or firewall.

## Before handing over a change

Run from the repository root in the isolated environment:

```sh
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
python -m bandit -c pyproject.toml -r src scripts
python scripts/check_secrets.py
python scripts/audit_dependencies.py
```

The secret gate scans exact regular-file blobs from the Git index in a private
temporary snapshot. Stage all intended changes, then run it before commit.
Unstaged content is not scanned and changing the index requires another run.
Both staged and current ignore rules are enforced; tracked working paths must
also remain regular, present and inside the repository.
Review staged paths and diffs yourself. Do not add broad secret allowlists or
advisory exceptions to obtain a passing gate. Dependency auditing needs advisory
service access; an unavailable service is an incomplete check.

Describe the problem, resulting behavior, validation and remaining limitations in
the PR. Report checks actually run, including interpreter version. GitHub Actions
is manual-only: a push or PR does not run CI. Maintainers must dispatch and inspect
both jobs when validating a release. Use the [security policy](SECURITY.md) for
potential vulnerabilities rather than posting sensitive evidence publicly.
