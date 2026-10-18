# Step 10: packaging and acceptance validation

## Status on 2026-10-18

Local packaging and automated acceptance checks passed on macOS with Python
3.14.3. Step 10 is **partially complete**, not a release approval: Python
3.11/3.12 execution, remote CI and browser appearance review remain pending.
No package was published, tag created, workflow dispatched or commit made by the
validation process. No live Linux host-security assessment was performed.

## Candidate and filesystem isolation

Artifacts were built from the tracked working-tree files at commit
`002da5d` (`docs: add contributing, security, and release preparation documentation`).
The later test correction in `tests/checks/test_filesystem.py` (now committed as
`a7c6416`) was not included in those artifacts. It does not change runtime code.
The 317-test run used that corrected test file against the installed wheel.
This document is a subsequent validation record, not part of the tested archive.

Source copies, build output and virtual environments were created under
`/private/tmp`, keeping build metadata out of the checkout. A separate build
environment used build 1.6.1 and setuptools 84.0.0. The build produced an sdist
and then built the wheel from that sdist:

```sh
/private/tmp/hardcheck-step10/bin/python -m build --no-isolation \
  --outdir /private/tmp/hardcheck-step10-dist \
  /private/tmp/hardcheck-step10-source
```

The build succeeded with a setuptools deprecation warning about the existing
TOML-table license declaration. Migrating to SPDX metadata requires reviewing the
minimum setuptools version; the warning has not been suppressed or fixed here.

Artifact SHA-256 values for this local build (not a reproducible-build claim):

- `hardcheck-0.1.0-py3-none-any.whl`:
  `dde040ad2c1cb141a7b859f7e3fbaf6a5cf9eb686871067f6e0506e0ed7ba16e`
- `hardcheck-0.1.0.tar.gz`:
  `04a122f8f91a3d98fccbea30c3876ba83788a0fb1199261a1c11d0cd6293bc42`

Archive inspection confirmed the license, both catalogs, HTML template and CSS.
The inspected archive paths contained no `.env`, virtual-environment or local
scan-output entries. This is a packaging check, not a comprehensive secret scan
of binary artifacts or repository history.

## Fresh installations and acceptance

Two new virtual environments were created outside the checkout. One installed
the wheel; the other built and installed the source archive. All dependencies
came from wheels already present in the local pip cache, copied into a temporary
wheelhouse. No additional network access was used for these installations.
The source install used preinstalled setuptools and `--no-build-isolation`.
This validates offline installation with the available versions, not every
version allowed by the dependency constraints.

Representative installation commands, after creating the virtual environments:

```sh
WHEELHOUSE=/private/tmp/hardcheck-step10-wheelhouse
DIST=/private/tmp/hardcheck-step10-dist
/private/tmp/hardcheck-step10-wheel-env/bin/python -m pip install \
  --no-index --find-links="$WHEELHOUSE" "$DIST/hardcheck-0.1.0-py3-none-any.whl"
/private/tmp/hardcheck-step10-sdist-env/bin/python -m pip install \
  --no-index --find-links="$WHEELHOUSE" setuptools
/private/tmp/hardcheck-step10-sdist-env/bin/python -m pip install \
  --no-index --no-build-isolation --find-links="$WHEELHOUSE" \
  "$DIST/hardcheck-0.1.0.tar.gz"
```

Both installations passed acceptance checks executed from `/private/tmp`:

- Imported application code was under the selected virtual environment, not the
  source checkout. Installed `hardcheck --version`, `--help` and `list-checks`
  entry points worked; version was 0.1.0 and all 18 IDs were present.
- Injected synthetic results for all 18 checks rendered terminal, JSON and HTML
  in English and Turkish. No live probes were executed for these fixtures.
- PASS/WARN/SKIP returned 0, FAIL returned 1, and ERROR returned 2. Hiding low
  severity errors behind a critical filter retained exit code 2 with empty output
  selection. JSON language and finding counts matched expectations.
- Reports written to new files matched stdout and had mode 0600. Reusing the
  same path failed without modifying the existing contents.
- A policy disabling all 18 checks and overriding severity loaded successfully;
  results were SKIP with the selected severity. `pip check` passed in both
  environments.

Runtime dependencies in both clean environments were PyYAML 6.0.3, Jinja2 3.1.6,
MarkupSafe 3.0.4, rich 15.0.0, markdown-it-py 4.2.0, mdurl 0.1.2 and pygments
2.21.0. The local smoke harness and build artifacts are temporary files, not
committed project tools. Existing automated integration tests cover the same
reporting contracts and additional adversarial cases.

## Automated quality and security results

The isolated validation environment passed:

- 317 tests, 97% statement coverage, against the installed wheel on Python 3.14.3.
- Ruff 0.17.1, Bandit 1.9.4 and `pip check`.
- Offline secret gate: 80 tracked paths, no findings. The gate reads current
  working-tree contents for indexed paths; it therefore included the modified
  existing test, but not this newly created document. Rerun after staging.
- Exact installed-dependency audit: no known vulnerabilities, with pip 26.2.1
  and pip-audit 2.10.1. This dated result applies to the validation environment;
  the two fresh installation environments were checked with `pip check`, not
  separately audited against the advisory service.

The first test run encountered a coverage-output permission error and a fixture
failure: this host's temporary filesystem reduced requested mode 04600 to 0600.
Coverage data was redirected to `/private/tmp`. The test correction replaces the
host-dependent setuid case with injected metadata for setuid, setgid and sticky
bits on both sensitive-file checks. Production permission evaluation is unchanged;
all 317 tests passed after correction.

## Remaining release gates

- Execute Python 3.11 and 3.12 checks; only Python 3.14 was available locally.
- Dispatch and inspect manual CI for the final committed candidate, including
  both quality interpreters and the security job.
- Review synthetic HTML at desktop/mobile sizes and in print preview, including
  Turkish, long text, empty reports and network activity.
- After committing the final candidate, repeat applicable checks and record its
  exact commit. Decide publication separately using [release preparation](RELEASING.md).

These pending checks prevent describing this milestone as fully verified or the
package as release-ready. The results above do not certify a Linux host's security.
