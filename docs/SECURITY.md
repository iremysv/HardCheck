# Security policy

HardCheck is under development at version 0.1.0. No released-version support
window or response-time commitment is established. Fixes are prepared against
the current development code; older snapshots are not guaranteed backports.

## Reporting a suspected vulnerability

Use the repository's private vulnerability reporting feature if its Security tab
offers it. No dedicated security email or private reporting endpoint has been
configured or verified by this project. If private reporting is unavailable,
open a minimal public issue asking maintainers for a private channel. Omit exploit
details, affected host data and credentials until a private channel is agreed.

A private report should contain the affected commit/version, Python/OS versions,
expected and actual behavior, impact, and minimal reproduction using synthetic
files. Include relevant check IDs and exit codes. Never send real shadow records,
secret values, full host reports or private configuration. Coordinate disclosure
and remediation with maintainers; no acknowledgment deadline is promised here.

If credentials were exposed, revoke or rotate them promptly. Removing a file or
commit from the current tree does not remove previously disclosed copies.

## Scope and interpretation

Useful reports include unintended writes or execution, sensitive evidence leaks,
unsafe policy/template handling, unbounded input processing and incorrect success
results. Known limitations are documented in the [threat model](threat-model.md)
and per-step scope notes. A suspected bypass of an implemented boundary should
still be reported even when related limitations exist.

Run with an ordinary account. PASS and the score describe bounded checks, not a
certification of host security. WARN, SKIP and ERROR do not establish compliance.
Container observations may cover only the current namespace. Remediation guidance
is manual and requires assessment for the target system.

Maintainers should reproduce privately with synthetic fixtures, assess impact,
add regression coverage, rerun the [security gates](step-08.md), and document
affected versions and remaining limits before coordinating publication. Do not
place confidential reports or live exploit data in the repository.
