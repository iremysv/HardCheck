# Step 3: local account and filesystem checks

Eight implementations join the four SSH checks, for twelve registered controls.
Implementations were delivered in related, tested commits: local account records,
password defaults, sensitive metadata, bounded tree traversal and integration.
GitHub quality checks are now manual (`workflow_dispatch`) at user request;
local lint and tests remain part of development. Earlier run records are retained.

## Local accounts and password defaults

- USR-001 reads only the local shadow database, rejecting empty password fields.
  Locked markers are nonempty. No account names or password values reach results.
  File absence yields SKIP; denied access and empty databases yield WARN.
  Malformed/duplicate records make coverage partial; a valid record with an
  empty password still yields FAIL, otherwise partial coverage yields WARN.
  It does not assess NSS/LDAP, PAM nullok, hash strength,
  account expiry or whether a nonempty hash allows authentication.
- USR-002 requires exactly one UID-zero account, named root, in local passwd.
  Fields, duplicate names, bounded numeric UID/GID syntax and range are validated.
  A valid non-root UID-zero record yields FAIL even alongside malformed records,
  regardless of record order. Partial coverage is reported explicitly and cannot
  establish compliance or prove that the root account is absent.
  NSS/LDAP identities and user namespaces are outside this static scope.
- USR-003 checks a single explicit PASS_MAX_DAYS default in login.defs: 1–90.
  Duplicate/missing/invalid settings yield WARN. This default affects new accounts;
  existing account expiry is not inspected. It is an assignment policy, not a
  universal recommendation for every authentication deployment.
- USR-004 reads pwquality.conf.d snippets in sorted order, then the main file.
  Later assignments override earlier ones. Explicit minlen minus the sum of
  positive character credits must be at least 12, and enforcing must not be zero.
  Credit defaults are zero. Missing main policy yields WARN; vendor fallback is
  not evaluated. PAM activation, PAM argument overrides, root exemptions, alternate
  config paths and existing password lengths are not evaluated. PASS describes
  this static configuration, not a verified system-wide enforcement guarantee.

Reads are bounded regular-file reads. Shadow/passwd/login.defs have a 256 KiB
limit. Password quality files have a 64 KiB individual and 1 MiB total limit,
128 snippets and 1024 directory entries maximum. Errors produce sanitized WARN.
No automatic privilege escalation, command execution or configuration writes occur.

## Filesystem scope

FS-001 requires root ownership and exact mode 0644 on a regular passwd file.
FS-002 requires root ownership and mode bits that are a subset of 0640 on a
regular shadow file: 0600/0400/0000 are allowed; 0604/0620 and special bits fail.
The identity and membership of a group with read access are not audited here.
FS-003 checks a root-owned directory and sticky bit; it does not mandate mode
1777 or assess separate mount options. These checks use lstat and report WARN
for final symlinks. Parent path trust and extended ACLs are not evaluated.

FS-004 inspects regular files beneath /etc via descriptor-relative directory
opens using O_NOFOLLOW. It does not read file contents, follow symlinks, traverse
other devices, or inspect special files. Directory/file counts are not a complete
ACL or effective-permission audit. Cross-device entries, permission errors, races
and resource limits make coverage incomplete. Known world-writable files produce
FAIL even when coverage is incomplete; otherwise incomplete coverage yields WARN.
Limits: 20,000 entries and depth 64. Findings contain counts, not private names.
Directory replacements are checked by device/inode; scans are not atomic snapshots.
Platform/environment detection is scheduled for step 4; this release targets Linux.

## Validation

Unit tests inject temporary files and permission failures. Integration tests inject
all twelve check targets, then exercise the registry, YAML policy, engine and CLI
without scanning real /etc, shadow or passwd data. Fixtures include disabled
checks, restrictive permissions, malformed records, snippet overrides, symlink
escapes, replacement races, traversal limits and partial scan failures.

## Primary references

- https://man7.org/linux/man-pages/man5/shadow.5.html
- https://man7.org/linux/man-pages/man5/passwd.5.html
- https://man7.org/linux/man-pages/man5/login.defs.5.html
- https://github.com/libpwquality/libpwquality/blob/master/doc/man/pwquality.conf.5.pod
- https://man7.org/linux/man-pages/man7/inode.7.html
- https://man7.org/linux/man-pages/man2/chmod.2.html
