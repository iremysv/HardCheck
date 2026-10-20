# HardCheck 0.1.0 release summary

Prepared on 2026-10-19. This document describes the initial implementation;
it does not announce package-index publication or a GitHub release.

## Included functionality

- Eighteen read-only checks for SSH, local accounts, password defaults,
  filesystem permissions, firewall evidence, legacy listeners/services and sysctl.
- Strict YAML policy overrides for enabled checks and severity.
- English and Turkish terminal, JSON and self-contained offline HTML reports.
- Explicit PASS, FAIL, WARN, SKIP and ERROR outcomes, sanitized evidence,
  environment scope, conditional compliance scoring and assessment coverage.
- Bounded file reads and fixed read-only commands without automatic remediation.
- Wheel/source packaging and installed-artifact acceptance checks.

The latest account fix preserves confirmed empty-password and non-root UID-zero
violations when other records are malformed or duplicated. Partial inventories
are labelled and cannot prove compliance or absence of the root account.

## Installation

From a checkout, using Python 3.11 or newer:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
hardcheck --version
hardcheck list-checks
hardcheck scan --lang tr --explain
```

Run scans as an ordinary Linux user. Exit code 0 means no displayed FAIL and no
internal error; it does not establish full compliance. Exit code 1 indicates
displayed FAIL results when there is no internal error. Exit code 2 takes
precedence for internal errors (even when filtered out), invalid input or report
rendering/writing failures. WARN/SKIP are not proof of compliance. On non-Linux
systems, checks return SKIP; development tests on macOS use fixtures.

## Validation and limits

The exact validated commit and CI evidence are recorded in
[final validation](final-validation.md). The implemented scope and acceptance
checks are complete; this is not comprehensive Linux security certification.
Live host behaviour, distribution differences and effective PAM/SSH enforcement
remain subject to the documented per-check limits.

See the [English README](../README.md), [Turkish README](../README.tr.md),
[threat model](threat-model.md) and [release procedure](RELEASING.md).

## Local application extension

The working tree now includes `serve`, user-level Linux launcher installation,
authenticated loopback scanning and automatic panel results/exports. Evidence
collection for NET-002 now includes observed listener counts and coverage, with
unchanged status decisions. See [local application](local-application.md) for
the separate validation record and pending Ubuntu/UTM acceptance. This does not
change the earlier release validation record or announce a published release.
