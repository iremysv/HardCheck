# Step 9: contribution, security and release documentation

This milestone establishes the maintainer workflow for the existing read-only CLI:

- [Contributing](CONTRIBUTING.md): isolated setup, implementation boundaries,
  synthetic fixtures, local quality/security gates and manual CI expectations.
- [Security policy](SECURITY.md): safe reporting, development support scope and
  maintainer triage. A dedicated private contact is not configured; private
  repository reporting must be checked before sending sensitive details.
- [Release preparation](RELEASING.md): candidate review, version consistency,
  artifact inspection, fresh wheel/source installs and acceptance checks.

These documents live under `docs/`. In particular, `docs/SECURITY.md` provides a
standard repository security-policy location. This milestone does not publish a
package, change runtime behavior, dispatch CI, create a tag or make a commit.

The instructions were checked against the current package metadata, CLI flags,
manual workflow and security wrappers. Documentation links and declared version
consistency are checked locally. No new runtime test result or security-audit
result is claimed for this documentation-only step.

## Next: step 10

Execute clean-install and final validation, recording actual outcomes rather than
assuming checklist completion. Carry forward Python 3.11 execution, remote CI
and browser appearance review as pending from steps 7–8. The current release
checklist does not mark any of these as passed.
