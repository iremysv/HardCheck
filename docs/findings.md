# Finding explanations and safe evidence

Step 5 adds consistent expected values, rationale and manual remediation guidance
for all eighteen registered checks. Run `python -m hardcheck scan --explain` to
show these fields, numeric/token observations and a reference for each finding.
The compact default output and existing exit-code semantics remain available.
Scoring, JSON/HTML output and English/Turkish presentation are now available;
see [reporting](reporting.md) and [step 7](step-07.md).

## Data model

CheckResult retains its stable check ID, category, severity, status, reference,
localization keys and scope detail. It adds title, expected, rationale, remediation
and an immutable tuple of Evidence items. Policy severity overrides preserve the
explanation and observations. No result interpretation upgrades WARN/SKIP to PASS.
Disabled, unavailable or failed assessments default to `assessment=unknown`;
absence of evidence is not evidence of compliance.

Evidence keys are enum members. Values must be enum tokens or bounded integers;
arbitrary strings, booleans, objects and out-of-range numbers are rejected.
Sensitive strings are omitted rather than partially masked: account names,
password fields/hashes, paths, addresses and raw package/firewall output never
enter structured evidence. Non-recognized setting strings become `invalid`.
Code may retain source content briefly while parsing; this is not secure-memory
zeroization or a promise that process memory contains no secrets.

## Observations by family

- SSH: recognized yes/no token or bounded decimal setting; invalid strings are
  replaced by an invalid token. Include/Match uncertainty yields unknown evidence.
- Accounts: inspected-record and noncompliance counts, without account identities.
  For UID 0, counts include unexpected privileged accounts or a missing root UID 0.
- Password defaults: numeric configured age/length, positive credits and enforcing.
  Password age is a new-account default, not existing-account expiry. Password
  quality configuration does not prove PAM activation or effective enforcement.
- Filesystem: numeric owner UID and mode bits, sticky-bit state, offending-file
  count and traversal coverage. Counts do not reveal private file names. Extended
  ACLs, group membership and parent path trust are still outside this assessment.
- Sysctl: numeric current-namespace observations, or unknown/invalid tokens.
- Listeners: the current probe returns a status and a fixed namespace/port
  limitation; its structured evidence remains `assessment=unknown`. Listener
  counts are not currently emitted. Addresses are excluded.
- Firewall: recognized backend token when active filtering evidence exists;
  otherwise scope-limited coverage. Backend evidence does not certify rule quality.
- Services: known-package/unit presence or absence within successful inventories,
  alongside coverage. Partial inventory observations do not prove universal absence.

A `complete_within_scope` token refers only to the documented inputs. It is not a
host-wide security certification. Scope limits from step-02/03/04 documents still
apply. Environment/namespace context stays attached to results.

## Manual remediation

Guidance describes preconditions and review steps; it is never executed. SSH
changes require a separate tested login/recovery route and configuration validation.
Forwarding changes require checking router/VPN/container workloads. File changes
must be targeted and reviewed, not recursive chmod operations. Package removals
require dependency and service-owner review. Unknown/error outcomes require
resolving visibility or applicability before treating remediation as necessary.
The configured assignment policy may differ from an organization's security policy.

## Validation

Tests cover guidance for every registered check, rejected arbitrary evidence,
immutability, invalid/secret setting suppression, numeric/count evidence, sensitive
path/content suppression and explained CLI output with unchanged exit status.
All inputs use temporary files or injected query results. No remediation runs.
