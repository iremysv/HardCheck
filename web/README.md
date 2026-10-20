# HardCheck web interface

A buildless report viewer. Serve `dist/` with a static HTTP server:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory web/dist
```

Open http://127.0.0.1:4173. The bundled Turkish report is synthetic and labelled.
JSON uploads (schema version 1, at most 5 MB) stay in browser memory. Nothing is
uploaded or persisted. Refreshing restores the demonstration. In static mode the viewer does
not run Linux probes or change system settings. Installed `hardcheck serve` adds
the authenticated local scan controls; see [local application](../docs/local-application.md). Imported text is rendered with
textContent, and reference links allow only HTTP/HTTPS.

Filters cover status, severity, title/category/identifier search. Expand a finding
for evidence, rationale and remediation; download exports the full loaded report,
not only the visible filter. Source reports can be English or Turkish; UI labels
are Turkish. Scores use displayed PASS/FAIL findings only; excluded source
controls are counted separately. Zero findings do not imply compliance.

The site remains an independently deployed static companion. Wheel builds also
include these canonical assets for the local application. Static hosting does
not expose the local API or enable real scans. The `.openai/hosting.json` file records its private Sites identity.

## Console layout

The dark console follows the supplied video reference: fixed navigation, overview
cards, a conditional score ring, category breakdowns and actionable findings.
Hash routes provide Overview, Findings, Reports and Help screens. The report list
keeps at most ten entries in memory for the current tab session; no localStorage
is used. The sample-report dialog filters the bundled synthetic data by category
and recalculates exported summary fields. It never starts a live scan.

Run functional tests with `node --test web/tests/report.test.cjs`.
These tests use a DOM stub and do not establish visual browser correctness.

## Review and comparison tools

Findings default to ERROR, FAIL, WARN, SKIP, PASS order, with severity and check
identifier as tie-breakers. Users can sort by identifier or title, page through
10/25/50 findings, and clear filters. Changing filters resets pagination.
Dashboard counts and full-report downloads remain independent of UI filters.

Reports can be compared by check identifier within the current session. Only
FAIL → PASS is labelled resolved and PASS → FAIL is labelled a new noncompliance.
Other status transitions, severity changes and controls present in only one
report are distinguished. Text/evidence changes are not compared; the user must
verify that reports refer to the same system. No host identity is inferred.

A scope notice surfaces source-filtered controls and hidden ERROR counts reported
by scan_summary, and clarifies the limits of the displayed score. Imported reports
are supplied data, not independently authenticated scan results.

## Local panel clarity

In local mode the real scan is the primary action; sample scans remain available
in Help. Static mode retains the sample heading action. Five separate outcome
counts and assessed/total coverage come from the loaded report. Displayed-report
JSON exports are labelled separately from the local service's latest-scan JSON
and HTML exports. Local history entries remain identified as previous scans.
