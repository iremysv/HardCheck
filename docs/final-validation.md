# Audit fixes and current validation (2026-10-18)

The identified code and packaging defects have been corrected. Local acceptance
is complete on macOS and final remote Linux CI passed for commit `c54ffd6`.
The maintainer committed and pushed the candidate; the agent dispatched and
inspected the manual workflow. This is not a published release or a
claim that no further defects can exist. Earlier step documents retain their
historical test counts and artifact hashes.

## Corrected findings

- SSH keyword parsing now accepts the optional equals separator for settings,
  Include and Match without changing equals signs inside arguments. First-value
  precedence is preserved. Synthetic examples were compared with local OpenSSH.
- Secret scanning snapshots exact staged regular-file blobs, without executing
  checkout filters. Working-tree edits cannot conceal staged candidates. Both
  staged and working ignore rules are enforced; private snapshots are cleaned
  up on failure. Stage intended changes and rerun after any index change.
- Source distributions contain scripts, every test, development documentation,
  examples and ignore rules. The packaging regression builds both distributions
  offline and checks imports, resources and exclusions. SPDX license metadata
  replaces the deprecated table declaration, using setuptools >=77.
- TCP and service parsers continue after malformed individual records. Known
  forbidden evidence still produces FAIL regardless of record order; partial
  inventories without such evidence remain uncertain.
- JSON retains sanitized environment metadata, localized safe notes and stable
  execution reasons. Filtered reports retain collected environment context.
- Installed-artifact acceptance is a committed tool rather than a temporary
  harness: `scripts/validate_install.py`. It rejects source-checkout imports and
  never runs live security probes. Manual CI now validates fresh wheel/source
  installs on both supported matrix interpreters.
- HTML wraps long headings and empty-score labels, constrains table columns and
  keeps horizontal table scrolling inside its container. A reusable browser
  tool covers full, empty and unusually long synthetic reports in both languages.
- Both READMEs link current contribution, security, release and validation docs.

## Local evidence

Full automated suites passed on Python 3.11.17, 3.12.15 and 3.14.3: 403 tests per
interpreter, with 97% application statement coverage. Fixtures use temporary data
and injected probes; this is not live Linux-host certification.

Fresh wheel and source installations each passed `scripts/validate_install.py`
on Python 3.11 and 3.12 (four independent environments). The checks cover the
installed entry point, all 18 IDs, three output formats, English/Turkish, all five
statuses, hidden errors, empty selection, policy metadata, private files,
overwrite refusal and `pip check`. Installations used already cached dependencies
offline. Source builds used explicitly installed setuptools without build
isolation. No package-index publication occurred.
The final extracted source archive also passed all 403 tests on Python 3.12.

Ruff and Bandit passed. The exact installed Python 3.12 validation environment
dependency audit reported no known vulnerabilities. Its advisory lookup used
network access for package names/versions only; cache warnings caused stale
entries to be ignored, not advisory failures to be accepted.

The staged secret gate is separate from testing working-tree changes. It must
be run after staging the final candidate, including the newly added tools/docs.
Historical scan results do not cover later unstaged edits.

## Browser evidence and reproduction

Chromium 148.0.7778.96 passed 18 cases: English/Turkish × full/empty/long reports ×
desktop (1280px), mobile (390px) and print media (794px). Each had the expected
sections/language, no page-level horizontal overflow, no page errors and no
external network requests. Screenshots of desktop/mobile findings, Turkish empty
metrics and print styling were visually inspected after the CSS correction.
This covers Chromium print-media rendering, not every printer or paginated PDF.

Playwright is optional review tooling, not a runtime dependency or a prerequisite
for the ordinary test suite. To repeat in an isolated review environment:

```sh
python -m pip install playwright
python -m playwright install chromium
PYTHONPATH=src python scripts/validate_html_layout.py --output /path/to/new-directory
```

An optional `--browser /path/to/chromium` uses an existing executable. The output
directory must be new; it contains only synthetic HTML, screenshots and
`results.json`. The tool blocks external requests. Keep generated review output
outside the repository or in an ignored directory. Local review output is under
`/private/tmp/hardcheck-browser-final` and may be removed by the operating system.

## Remote CI and closure

[Manual run 39155659273](https://github.com/iremysv/HardCheck/actions/runs/39155659273)
tested commit `d17984f432a92bbac2bf9668c7a4bd26eba9584e`. Its security job passed;
both quality jobs stopped at Ruff E501 in `environment.py`. That formatting
correction was included in the completed candidate. This failed run is retained
as historical evidence, not claimed as successful CI.

[Manual run 39156508122](https://github.com/iremysv/HardCheck/actions/runs/39156508122)
passed for `c54ffd6237716f4a23498db05e78c8c6948d5550`. Both Linux quality jobs
(Python 3.11 and 3.12) passed lint, tests, dependency consistency and fresh wheel
and source installation acceptance. The security job passed Bandit, staged secret
scanning and exact installed-dependency auditing. All jobs completed successfully.
This closes the previously pending interpreter, artifact and remote CI checks.

No automatic push/PR triggers were added. Commit ownership remains with the
maintainer; the agent did not commit or push the candidate. This documentation
follow-up records the result after the successful run; runtime code is unchanged.
Future code/dependency changes require fresh validation before release.
No history rewriting or deletion of old branches is needed for the observed code
defects. Author email visibility is a separate privacy choice, not evidence of a
credential leak or computer access.
