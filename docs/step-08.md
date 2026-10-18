# Step 8: security audits and manual CI hardening

## Scope

This milestone adds dependency/secret auditing, static security analysis, targeted
regression tests, a threat model and hardened manual CI. It does not add security
checks, automatic remediation or web-panel features. Repository history is not
rewritten, and commits do not trigger Actions automatically.

## Reproduce the checks

Use an isolated virtual environment and install the optional developer/security
tools. The security extra includes a patched pip floor; upgrade the installer
before installing the remaining tools.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2,<27'
python -m pip install -e '.[dev,security]'
python -m pip check
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
python -m bandit -c pyproject.toml -r src scripts
python scripts/check_secrets.py
python scripts/audit_dependencies.py
```

The tooling integration tests require the security extra, including detect-secrets.
Run from the repository root. Do not run these tools as root. Security tools are
optional development dependencies, not CLI runtime dependencies.

## Secret gate

`check_secrets.py` enumerates the Git index using NUL-separated paths and snapshots
its exact regular-file blobs in a private temporary directory. It rejects
unmerged/nonregular index entries and missing, escaping or nonregular working
paths. Both staged and current ignore rules reject force-tracked ignored files.
Git checkout filters are never executed. The snapshot is removed after scanning,
including when the detector fails. Disk edits cannot hide staged secret candidates.
It invokes all default detect-secrets plugins with `--no-verify` against only those
staged files. Candidates never reach a credential-verification service. There
is no baseline that silently accepts a set of existing findings. Stage all intended
changes before scanning; unstaged content and history are outside this gate. A
later index change requires rerunning it. The scan does not lock the index across
the later commit operation.

The detector's scan command ordinarily exits zero even with findings; the wrapper
examines its JSON and returns 1 when findings exist. Errors, warnings, invalid
responses or unreadable inputs return 2. It prints only paths, line numbers and
detector names, not secret values or their hashes. Empty/incomplete scans cannot
be reported as clean. Git-ignored environments and local audit data must stay
untracked even when their current content contains no detector-recognized secret.

Two exact synthetic fixture lines carry reviewed allowlist comments. Additional
allowlisting requires reviewing the precise value and reason. The scanner is
heuristic and text-oriented; a clean current tree does not prove no historical,
untracked, encoded or binary secret exists. If a real secret is ever exposed,
revoke/rotate it; removing a current-tree file does not remove its Git history.

## Dependency gate

`audit_dependencies.py` snapshots normalized package names and exact installed
versions into a private temporary directory, then runs strict pip-audit with
resolution disabled. It audits runtime dependencies, transitive dependencies,
developer/security tools and pip. It excludes only the unpublished HardCheck
project itself. All remaining installed versions must be collected and audited;
there is no advisory ignore list or skip-editable workaround.

The temporary requirements snapshot is not a lockfile, does not verify package
hashes, and is not installed. Advisory service requests disclose names/versions,
not source files or secret candidates. Network/advisory failures are failures,
not evidence of a clean environment. The audit has a three-minute total process
limit and a 15-second request timeout.

On 2026-10-18 the original environment's pip 25.0.1 produced advisory findings.
After upgrading to pip 26.2.1, the exact installed-environment audit reported no
known vulnerabilities. No application dependency was removed to hide findings.
This result is dated and applies to the resolved local environment; rerun it
when dependencies or advisories change.

## Static analysis and CI

Bandit analyzes application and repository-tool Python files with all rule IDs
enabled. Narrow reviewed exceptions are documented in the
[threat model](threat-model.md). Ruff and the existing test suite remain required.

CI is still `workflow_dispatch` only. Existing checkout v4 and setup-python v5
references are pinned to verified full commit hashes. Both jobs use read-only
contents permissions, disable persisted checkout credentials and stop after
15 minutes. The quality job retains Python 3.11/3.12 and installs both optional
tool groups; the security job runs Bandit, offline secret scanning and dependency
auditing on Python 3.12. No workflow secrets or write permissions are introduced.

The workflow was checked locally for YAML structure, its manual-only trigger,
permissions, full-SHA action refs and credential settings. It was not dispatched
remotely during this milestone. Future maintainers must review/update pinned
commits rather than replacing them with moving tags.

## Verification

Tests include real detector runs against generated synthetic credentials in
temporary Git repositories; ignored local data stays out of the scan. Additional
tests prove findings/errors cannot pass, dependency pins cannot inject options,
forced tracked `.env`/virtual environments/cache/report files fail, and packaged
report source remains permitted by the ignore rules.

Read/query tests cover FIFO/directory rejection, byte rather than character
limits, strict UTF-8, minimal child environments, inherited stdout pipes and
process-group cleanup. A YAML Python-object payload is rejected without invoking
its constructor. No fixture changes live host security settings.

The local Python 3.12 validation passed 312 tests, Ruff, Bandit, pip check, the
tracked-tree secret gate and the installed-dependency audit. Python 3.11 execution
and remote GitHub Actions results are not claimed. The earlier browser appearance
review remains pending; this step does not upgrade that result to verified.
