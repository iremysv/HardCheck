# HardCheck threat model

## Purpose and assets

HardCheck is a read-only local Linux hardening checker. Protect configuration and
credential confidentiality, avoid modifying inspected systems, preserve truthful
PASS/FAIL/WARN/SKIP/ERROR results, and prevent reports or build tooling from
executing untrusted content. A high score is not a security certification.

Run as an ordinary account. Missing visibility is an uncertain outcome rather
than a reason to elevate privileges. No automatic remediation is implemented.

## Actors and assumptions

Inspected files, YAML policies and query output may be malformed or hostile.
A user may accidentally select an existing output path or stage private local
files. A dependency, action tag or advisory service may change independently.

The Python interpreter, installed HardCheck code, bundled guidance/templates,
repository checkout, Git executable and administrator-controlled OS facilities
are trusted. A root-level attacker or a compromised interpreter can defeat these
controls. Auditing an already compromised host cannot prove the host is clean.
Development tooling executes in a trusted, isolated environment, not under sudo.

## Boundaries and controls

| Boundary | Threat | Implemented control | Remaining limit |
| --- | --- | --- | --- |
| Local files → parser | FIFO/device blocking, malformed text, excessive content | Nonblocking opens, regular-file checks, byte limits, strict UTF-8 | Byte limits are not a global wall-clock deadline for filesystem calls |
| SSH/includes → findings | Includes, Match ambiguity or untrusted values create false PASS or leak content | Bounded include traversal; explicit uncertainty; allowlisted evidence | Static configuration does not prove the running daemon's effective settings |
| YAML → engine | Object constructors, aliases, duplicate keys, executable rules | SafeLoader subclass, nesting/size bounds and strict versioned metadata schema | Trusted installed check classes remain the executable implementation |
| Query name → process | Shell injection, attacker PATH, inherited credentials, hanging children | Fixed argv, trusted binary locations/ownership/modes, no shell or elevation, minimal environment, time/output bounds, process-group cleanup | A hostile OS, executable replacement race or uninterruptible kernel I/O is outside this guarantee |
| Probe result → public evidence | Usernames, hashes, private paths or raw output leak | Enum keys/tokens and bounded integers; fixed guidance; raw detail omitted or allowlisted | Source contents can exist briefly in process memory; no secure-memory zeroization |
| Findings → HTML | Script, markup or attribute injection and unsafe links | Always-on Jinja escaping, StrictUndefined, HTTPS-only references, no active resources, hashed stylesheet CSP | Bundled template/CSS integrity is trusted; a clicked external reference opens that site |
| Report path → disk | Overwrite, final symlink traversal or world-readable audit file | Exclusive creation, owner-only 0600 permissions, no overwrite flag | Users must choose a trusted parent directory; ancestor symlink/race protection is not claimed; failed writes may leave a partial new file |
| Git index → publication | Staged credentials are hidden by working-tree edits; ignored local files get force-added | Private snapshot of exact staged regular-file blobs, no checkout filters; staged and current ignore rules enforced; offline detector fails on findings | Unstaged content/history are not scanned; rerun after index changes; heuristic detectors can miss secrets; inline allowlists require review |
| Installed packages → advisory service | Known vulnerable dependencies or incomplete audit treated as clean | Exact installed-version snapshot; strict pip-audit with finite timeout; no ignored advisories | Only the current environment and available advisories are checked; not every allowed dependency version; no package-integrity or unknown-vulnerability guarantee |
| Workflow → CI runner | Mutable actions, broad credentials or unlimited execution | Full action commit pins, contents:read, no persisted checkout credentials, 15-minute job bounds, manual triggers | Runner image and package/advisory infrastructure remain external dependencies |

## Security gate behavior

The tracked-file gate includes tests and documentation. It refuses tracked
symlinks, unsupported file types, paths escaping the repository, missing files,
ignore-policy violations, detector errors/warnings and malformed detector output.
Candidates are never verified against external credential services. Logs include
locations and detector names, never candidate values. A finding returns 1; an
incomplete scan returns 2. Neither is a clean result.

The dependency gate audits all installed distributions, including developer tools
and pip. Only this unpublished `hardcheck` distribution is deliberately excluded
from advisory lookup; its source is tested and statically analyzed. The temporary
exact-pins file is not a committed lockfile. It describes what is installed, not
package provenance or artifact integrity. Dependency names and versions are sent
to the advisory service; source files and credential candidates are not sent.
An unavailable service makes the gate fail, rather than silently pass.

## Static analysis exception review

Bandit scans `src` and `scripts` with every rule enabled. Tests contain deliberate
malicious fixtures and assertions and are exercised separately by pytest. There
are no whole-file exclusions or globally skipped Bandit rule IDs.

| Rule | Narrow reason |
| --- | --- |
| B105 | `Status.PASS` is a public outcome token, not a password |
| B108 | The existing `/tmp` directory is inspected by lstat; no temporary file is created there |
| B404/B603 | Application queries use fixed allowlisted argv and no shell; repository tools use fixed modules/flags, validated pins and a resolved Git executable |

The custom YAML loader is constructed/disposed explicitly; it inherits SafeLoader
and rejects Python object tags. B506 is not globally suppressed. The only secret
allowlist comments identify a synthetic passwd record and an intentionally
rejected example.org URL. No entire test file or directory is exempted.

## Verification and open limits

Regression tests cover unsafe YAML constructors, special files, read bounds,
invalid UTF-8, private environment isolation, output overflow, inherited-pipe
children, HTML payloads, private output creation, secret detection, fail-closed
errors and force-added ignored files. Tests use temporary fixtures and synthetic
queries, not remediation commands.

The local step-8 run used Python 3.12. Python 3.11 remains in the manual CI matrix;
the updated remote workflow was not dispatched during development. Browser
appearance validation from step 7 remains unverified in this environment.
Review [step 8 validation](step-08.md), [reporting](reporting.md) and the individual
check scope documents before interpreting results.

These statements describe the step-8 evidence. Newer validation and resolved audit
findings are recorded in [final validation](final-validation.md), including exact
scope and the distinction between a local working tree and a remote commit.
