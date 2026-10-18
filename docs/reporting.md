# Reporting, scoring and exit codes

Terminal summaries, versioned JSON and self-contained HTML share the same score
and scope rules. Select English or Turkish with `--lang en|tr`. See
[step 7](step-07.md) for HTML security and localization limits.

```sh
hardcheck scan
hardcheck scan --explain
hardcheck scan --format json
hardcheck scan --format json --output scan-output/report.json
hardcheck scan --min-severity high
hardcheck scan --lang tr --explain
hardcheck scan --format html --lang tr --output scan-output/report-tr.html
```

Create the output directory yourself. Output files are created exclusively with
mode 0600 (subject to a stricter umask). Existing files and symbolic links are
rejected. No overwrite option is provided. Write failures return 2; a partially
written new file may remain if storage fails. Reports are local audit data:
keep them in ignored directories such as `scan-output/` or `reports/`.

## Equal-weight score and coverage

- Assessed controls = PASS + FAIL.
- Score = 100 × PASS / assessed controls.
- Coverage = 100 × assessed controls / selected controls.
- WARN, SKIP and ERROR receive no score and remain visible in status counts.
- No assessed controls means score N/A (JSON null).
- No selected controls means coverage N/A (JSON null).

Percentages are rounded to two decimal places. Severity does not change a
control's weight; policy severity overrides affect filtering only. A 100% score
with low coverage is not evidence of overall host security. Even a PASS can be
based on static or bounded observations; coverage measures conclusive outcomes
within the selected control set, not filesystem traversal or host completeness.
Disabled controls remain SKIP and lower coverage.

## Filter scope and exit codes

`--min-severity` selects displayed controls after policy severity overrides.
The score and coverage use that displayed set. JSON also includes `scan_summary`
for all collected controls, plus the number of hidden controls. Terminal and HTML output
show the hidden count and full-scan ERROR count when filtering hides controls.
The host namespace is always labeled unverified.

| Code | Meaning |
| --- | --- |
| 0 | No displayed FAIL and no collected ERROR; uncertainty may remain |
| 1 | At least one displayed FAIL and no collected ERROR |
| 2 | Any collected ERROR, invalid/unsupported input, or report rendering/write failure |

A hidden FAIL does not change exit 0; a hidden ERROR always produces exit 2.
WARN, SKIP and an empty selection must not be interpreted as compliance.
Argparse also returns 2 for malformed command-line arguments. Diagnostics use
stderr; JSON stdout contains one JSON document without terminal decoration.

## JSON schema version 1

Top-level keys: `schema_version`, `language`, `hardcheck_version`, `scope`, `summary`,
`scan_summary`, `findings`. Each summary includes all five status counts, total,
assessed count, score and coverage. Findings contain identifiers, category,
severity, status, guidance, reference and allowlisted evidence. Raw detail and
command output are omitted. Numeric mode bits are integers in JSON and octal
in terminal/HTML explanations. JSON and HTML always include guidance; `--explain` expands
terminal findings only. No timestamp, username, hostname or private path is added
to JSON. Each finding also includes additive `reason`, `note` and `environment`
fields. `note` is localized through the same allowlist as terminal/HTML, never a
copy of arbitrary probe detail. `reason` is a stable machine token: `probe_result`,
`disabled_by_policy`, `unsupported_platform` or `check_error`. Probe-specific
limitations and unavailable-file explanations are carried by the sanitized note.

An environment contains `system`, bounded `distribution`, allowlisted
`service_manager`, `container` (`detected` or `unknown`) and
`host_namespace_verified: false`. Missing environment data is null; lack of
container markers never means verified bare metal. `scope.environments` retains
distinct collected environments even when all findings are filtered out. Invalid
environment markers become `unknown`. These values come from structured engine
metadata, not by interpreting raw note strings. HTML and terminal also display
validated markers and allowlisted scope notes; arbitrary raw detail is not rendered.

`language` is an additive field in schema version 1. Field names, control IDs,
status/severity tokens, evidence tokens and numeric values do not change with
language. Human guidance and `scope.limitations` are localized. Consumers should
use machine tokens rather than compare translated prose.

Tests use synthetic findings and temporary destinations to verify mixed and
empty results, hidden errors, serialization, privacy, permissions, overwrite
refusal and symlink refusal without changing host security settings.
