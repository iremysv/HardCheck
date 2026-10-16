# Review of milestones 1 and 2

## Findings fixed

- Check constructors were outside the error boundary. Constructor and execution
  failures now produce sanitized ERROR results without aborting other checks.
- Disabled checks were constructed and their severity override was lost. They
  now produce policy-adjusted SKIP results without instantiation.
- Severity filtering could hide ERROR and return success. ERROR now determines
  the exit code before presentation filtering.
- Unimplemented language/output options could be silently accepted. Unsupported
  requests now fail before scanning. Terminal output includes limitation details.
- Python shell tokenization could treat single quotes and backslash escapes as
  valid SSH value syntax. Only double quotes are now recognized, without shell
  escaping. MaxAuthTries rejects Python-specific numeric notation.
- glob silently ignores unreadable directories. Explicit bounded directory scans
  now propagate uncertainty; unsupported directory patterns produce WARN.
- README files were placeholders and claimed future reporting as available.
  Both now document actual features, installation, checks and exit semantics.

## Remaining scheduled work

Milestones 3–4 add the 14 USR/FS/NET/KRN/SVC checks and environment awareness.
Milestones 5–7 add rich evidence/remediation, scoring, reports and localization.
Milestone 8 adds broader security CI and a threat model. Milestones 9–10 complete
contribution/security/release documents, clean installation and final validation.
These are planned features, not implemented capabilities of this commit.

## Known limits

See step-02.md. Static SSH analysis does not validate the whole daemon grammar,
inspect daemon startup flags or resolve per-connection Match conditions. WARN and
SKIP must remain visible limitations, not be interpreted as secure configuration.
Coverage numbers measure exercised lines, not absence of vulnerabilities.
