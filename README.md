# HardCheck

Read-only Linux security auditing CLI, implemented in Python 3.11+.

## Current status

The ten planned milestones are complete: eighteen SSH, local account,
filesystem, network, kernel and legacy-service checks; an isolated scan engine,
strict YAML policies and bounded read-only queries. Environment markers label
Linux distribution, init system and possible container scope. Quality checks can be started
manually from GitHub Actions on Python 3.11 and 3.12; commits do not trigger them.
A separate manual security job audits source, tracked secrets and dependencies.

Terminal summaries, transparent scoring, versioned JSON and offline HTML reports
are available in English and Turkish (`--lang en|tr`). The inspection remains read-only.
See [reporting, scoring and exit codes](docs/reporting.md),
[contributing](docs/CONTRIBUTING.md), [security policy](docs/SECURITY.md) and
[release preparation](docs/RELEASING.md). Step 10 validation and audit fixes are
recorded in [the current validation record](docs/final-validation.md).
Version 0.1.0 release notes are in [the release summary](docs/release-0.1.0.md).
Package-index publication remains a separate step; install from this checkout below.

## Install and run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m hardcheck --version
python -m hardcheck list-checks
python -m hardcheck scan
python -m hardcheck scan --explain
python -m hardcheck scan --format json
python -m hardcheck scan --lang tr --explain
mkdir -p scan-output
python -m hardcheck scan --format html --lang tr --output scan-output/report-tr.html
python -m hardcheck scan --config examples/policy.yaml --min-severity high
```

Use an ordinary account. Inaccessible configuration produces an explicit uncertain
result; do not elevate privileges merely to turn warnings into passes.

## Explain a finding

`scan --explain` adds expected values, safe observations, rationale, primary
reference and manual remediation guidance. Evidence uses fixed tokens and bounded
numbers, never account names, password fields, private paths or raw command output.
Unknown/partial observations are labeled explicitly. Guidance does not change the
system. See [finding evidence and limitations](docs/findings.md).

## Checks

| ID | Explicit policy |
| --- | --- |
| SSH-001 | PermitRootLogin no |
| SSH-002 | PasswordAuthentication no |
| SSH-003 | MaxAuthTries between 1 and 4 |
| SSH-004 | PermitEmptyPasswords no |
| USR-001 | No empty local shadow password field |
| USR-002 | Only root has UID 0 |
| USR-003 | Explicit new-account PASS_MAX_DAYS: 1–90 |
| USR-004 | Configured libpwquality length after credits: at least 12 |
| FS-001 | Root-owned /etc/passwd, exact mode 0644 |
| FS-002 | Root-owned /etc/shadow, mode subset of 0640 |
| FS-003 | Root-owned /tmp directory with sticky bit |
| FS-004 | No world-writable regular files in the traversed /etc scope |
| NET-001 | Supported active input-filtering evidence |
| NET-002 | No TCP listeners on ports 21/23, IPv4 and IPv6 |
| NET-003 | IPv4 and global IPv6 forwarding disabled |
| KRN-001 | Live randomize_va_space = 2 |
| KRN-002 | Live dmesg_restrict = 1 |
| SVC-001 | No known telnet/rsh packages or systemd units |

A static PASS does not prove the running daemon uses the inspected configuration.
Match blocks and unsupported or unreadable configuration produce WARN. See
[configuration and limits](docs/step-02.md) before interpreting results. See [step 3 scope](docs/step-03.md) for account,
password-policy and filesystem limits. See [step 4 scope](docs/step-04.md) for
network/namespace limits, query safety and unsupported service environments.

Exit codes: 0 means no displayed FAIL and no internal ERROR; 1 means a displayed
FAIL; 2 means invalid/unsupported input or an internal ERROR. WARN and SKIP are
not compliance evidence. Severity filtering affects displayed findings and FAIL
exit status; internal ERROR always returns 2, even if filtered from display.

## Development

```sh
python -m pip install --upgrade 'pip>=26.2,<27'
python -m pip install -e '.[dev,security]'
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
```

Security checks: [step 8](docs/step-08.md) and [threat model](docs/threat-model.md).

```sh
python -m bandit -c pyproject.toml -r src scripts
python scripts/check_secrets.py
python scripts/audit_dependencies.py
```

Tests use temporary files and injected failures rather than changing host settings.
Stage intended changes before running the secret gate; it scans exact staged blobs,
not unstaged edits. Never commit environments, private keys, credentials or local audit data.
The project is under active development; its current scope is not a complete
system security assessment. License: MIT.

## Ubuntu local application

Install the updated package, then run `.venv/bin/hardcheck install-launcher` once.
Open **HardCheck** in the application menu to launch the loopback service and
browser panel. **Gerçek taramayı başlat** runs the existing read-only engine;
JSON/HTML buttons export its completed result without rescanning. See
[local application setup, removal and acceptance](docs/local-application.md).
The CLI and standalone static viewer remain supported.
