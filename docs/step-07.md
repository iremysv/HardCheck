# Step 7: offline HTML and English/Turkish reports

## Delivered behavior

The 18 existing checks keep their original execution and scoring rules. This step
adds a shared sanitized report model, bundled English/Turkish catalogs, localized
terminal/JSON output and a self-contained HTML report.

```sh
python -m hardcheck scan --lang tr
python -m hardcheck scan --lang tr --explain
python -m hardcheck scan --format json --lang en
mkdir -p scan-output
python -m hardcheck scan --format html --lang tr --output scan-output/report-tr.html
```

Each output path must be new. Reports use UTF-8 and owner-only file permissions
(mode 0600, possibly restricted further by umask). Existing paths, including
symbolic links, are rejected. The directory is not created automatically.
Report contents go to stdout when `--output` is omitted; diagnostics use stderr.
A FAIL scan can write a complete report and still exit 1. A collected ERROR can
write a report and still exit 2. Rendering and write failures also exit 2.

## Language contract

- `--lang en` is the default; `--lang tr` selects Turkish presentation.
- All 18 controls have translated title, expected value, rationale and manual
  remediation. Human evidence labels, fixed limitations and scope notes are
  translated too. Directives, filenames, commands and product names stay literal.
- Check IDs, PASS/FAIL/WARN/SKIP/ERROR, severity/category machine tokens, JSON field
  names and evidence tokens remain stable. Translation never changes a result.
- JSON schema version 1 adds `language`; human guidance and the scope limitation
  sentence use that language. Numeric observations and summary calculations match
  across formats and languages. JSON remains one parseable document.
- English and Turkish catalogs have the same nonempty keys. Missing text lookups
  fall back to English; missing English keys are programming errors. Unknown
  control guidance retains the original text. Unsupported languages are rejected.
- `scan --lang` selects reports and application diagnostics; argparse help,
  command names, parser usage errors and `list-checks` IDs remain English/stable.
- `--explain` expands terminal findings. HTML and JSON always include guidance.

The source English guidance remains in `catalog.py`; tests require the English
translation catalog to match it. Add or update both languages when changing a
built-in control. Packaged resources are loaded by fixed language names, never by
user-provided template or translation paths. This step adds no new dependencies.

## HTML safety and layout

The bundled Jinja environment enables automatic escaping for every template and
uses StrictUndefined. Control titles, IDs, expected values, rationale, remediation,
category text, evidence and references cannot become HTML elements or attributes.
No user-controlled template or `safe` template filter is used.

Reference links are only enabled for explicit HTTPS URLs with a hostname, without
credentials, backslashes or control/space characters. Other references are plain
escaped text. Links carry `noopener noreferrer`, and the document sets a
no-referrer policy. Links require user navigation; no external assets are loaded.

The document includes no JavaScript, forms, images, frames, remote fonts or remote
stylesheets. A restrictive meta Content-Security-Policy denies resources by
default and permits only the SHA-256 hash of the bundled inline stylesheet.
Scripts, base URLs, objects and form submissions are explicitly denied.

The responsive layout includes a scope warning, score and coverage cards, all
five status counts, a findings table and detailed manual guidance. Statuses use
text labels as well as color. Empty selection shows an explicit no-conclusion
message and no fabricated perfect score. Filtered reports expose hidden counts
and full-scan ERROR counts. Host namespace verification is never implied.

HTML escaping is distinct from evidence minimization: raw probe detail is never
inserted into HTML or JSON. Terminal/HTML use translated allowlisted detail notes
and validated environment markers. Unknown arbitrary notes become a fixed review
message. See [finding limitations](findings.md) before acting on results.

## Validation and limits

Automated tests cover both languages, all three output formats, all five statuses,
exit precedence, hidden errors, empty selections, disabled policies, non-Linux
skip behavior, private file output, overwrite refusal and rendering failures.
Adversarial HTML tests cover element/attribute payloads, unsafe reference schemes,
resource-free markup and the stylesheet CSP hash. Catalog tests cover parity,
all control guidance, immutable catalog data and canonical machine values.

A wheel was built and installed into a separate directory. Its packaged catalogs,
CSS and template successfully rendered both languages with all 18 controls.
Checks were run locally on Python 3.12; Python 3.11 runtime execution was not
available in this environment. The existing manual CI matrix remains unchanged.

In the original step-7 run, browser screenshot validation could not run because the headless browser download
failed in the environment. HTML structure and security are tested, but desktop,
mobile and print appearance were pending. Newer Chromium screenshots and
print-media checks are recorded in [final validation](final-validation.md). The CLI does not
automatically open a browser. This is a static report, not a hosted web application.

As before, a high score does not certify host security. The scope is bounded and
may be a container namespace. WARN/SKIP/ERROR never count as successful controls,
and no remediation is executed.
