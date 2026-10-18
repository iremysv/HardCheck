# Release preparation

This is a maintainer checklist, not evidence that a release has been published.
The project declares version 0.1.0; package-index publication, signing and automated
release workflows are not configured by this milestone.

## Candidate review

1. Review the candidate diff and working tree. Exclude environments, credentials,
   local audit output and unrelated changes. Review new files before staging.
2. Keep `pyproject.toml` and `src/hardcheck/__init__.py` versions equal. Update both
   READMEs and relevant scope/reporting documents for changes in behavior. Record
   user-visible changes and migration requirements in release notes.
3. Run all [contributor checks](CONTRIBUTING.md), including `pip check`, on the
   final candidate. Run the secret gate again after staging new files. Record
   interpreter, exact candidate commit and dated audit outcomes; a historical
   clean result is not a current dependency assessment.
4. Manually dispatch CI for the candidate ref and inspect both jobs, including
   Python 3.11 and 3.12 quality results. Confirm the workflow remains manual-only,
   read-only and pinned to reviewed full action commit hashes.

## Packaging and clean installation

In an isolated build environment, install the build frontend and create both
distributions from the repository root:

```sh
python -m pip install build
python -m build
```

The development extra includes the offline build-test tools. The packaging
regression test builds both artifacts in a temporary copy and verifies source
archive completeness, packaged resources and SPDX license metadata:

```sh
python -m pytest tests/test_packaging.py
```

The source archive must contain the scripts imported by its tests, the complete
test tree, `.gitignore`, examples and development documentation. Run its full
tests from the extracted archive with developer/security tools installed, using
`PYTHONPATH=src python -m pytest`, to catch missing source-only files. The secret
gate itself requires a Git checkout; a source archive has no index.

Inspect the wheel and source archive for license/readme metadata, all application
modules, both language catalogs and HTML template/CSS resources. Exclude private
files and local reports. Install the wheel into a fresh environment outside the
checkout and run commands from outside the source tree so imports cannot hide
missing packaged resources. Repeat with the source distribution in another fresh
environment. These checks require actual generated artifact paths, not an editable
install of the working tree.

Verify `hardcheck --version`, `hardcheck --help` and `hardcheck list-checks` (18
registered controls). Exercise terminal, JSON and HTML output in English/Turkish,
including policy overrides, empty selection, hidden errors, exit codes and safe
output-file behavior. Use controlled fixtures for expected results; any optional
live Linux smoke scan must run as an ordinary account and keep reports private.
Do not interpret a live scan exit code 1 as a packaging failure without examining
the findings.

Open synthetic HTML reports in a browser at desktop/mobile widths and print
preview. Check Turkish text, long guidance, status labels, empty results and the
absence of external resource requests. Record what was actually inspected.

## Release decision

Resolve failed checks and record remaining limitations before selecting a release
commit. Tagging, pushing, publishing packages and dispatching remote workflows
are separate maintainer actions. This document does not perform them. Never
publish credentials or host reports as release artifacts. Preserve the exact
artifact filenames and hashes with the validation record if artifacts are shared.

See [step 10](step-10.md) for the local clean-install and acceptance results.
The earlier Python 3.11, remote CI and browser appearance checks remain pending
until new evidence explicitly records them as passed.
