# HardCheck web interface

A buildless report viewer. Serve `dist/` with a static HTTP server:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory web/dist
```

Open http://127.0.0.1:4173. The bundled Turkish report is synthetic and labelled.
JSON uploads (schema version 1, at most 5 MB) stay in browser memory. Nothing is
uploaded or persisted. Refreshing restores the demonstration. The viewer does
not run Linux probes or change system settings. Imported text is rendered with
textContent, and reference links allow only HTTP/HTTPS.

Filters cover status, severity, title/category/identifier search. Expand a finding
for evidence, rationale and remediation; download exports the full loaded report,
not only the visible filter. Source reports can be English or Turkish; UI labels
are Turkish. Scores use displayed PASS/FAIL findings only; excluded source
controls are counted separately. Zero findings do not imply compliance.

The site is an independently deployed static companion; Python packaging is
unchanged. The `.openai/hosting.json` file records its private Sites identity.

## Console layout

The dark console follows the supplied video reference: fixed navigation, overview
cards, a conditional score ring, category breakdowns and actionable findings.
Hash routes provide Overview, Findings, Reports and Help screens. The report list
keeps at most ten entries in memory for the current tab session; no localStorage
is used. The sample-report dialog filters the bundled synthetic data by category
and recalculates exported summary fields. It never starts a live scan.

Run functional tests with `node --test web/tests/report.test.cjs`.
These tests use a DOM stub and do not establish visual browser correctness.
