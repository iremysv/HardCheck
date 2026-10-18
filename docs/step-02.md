# Step 2: secure configuration foundation

HardCheck performs read-only, bounded regular-file reads. It does not invoke a
shell, execute YAML commands, change system settings, or request elevated access.
Only explicitly exported reports (implemented later) may write output files.

## Policy schema version 1

Use `hardcheck scan --config examples/policy.yaml`. The root must contain exactly
`version: 1` and a `checks` mapping. Each registered ID accepts only `enabled`
(boolean) and `severity` (low/medium/high/critical). Omitted checks retain built-in
behavior. Disabled checks produce SKIP, rather than disappearing. Unknown fields,
IDs, versions, duplicate keys, aliases and custom object tags are rejected.
Policies are capped at 64 KiB and 12 nested YAML nodes. Policies configure existing
checks; they never introduce executable checks, file paths or shell commands.
Policy severity overrides are user choices, not a certification of compliance.

## SSH evaluation boundaries

The static parser evaluates the four supported explicit directives, with the
first global value taking precedence. Whitespace and the optional `=` separator
after a keyword are supported, including for Include and Match. Equals signs in
argument values are preserved. Global Includes expand in lexical order;
relative paths use `/etc/ssh`, not the including file's directory. Unmatched
patterns are ignored. Double-quoted arguments and comments are parsed without shell escape expansion.
Wildcards in directory components and recursive globbing yield WARN; only the
final filename component supports patterns. Directory scans are capped at 4096
entries, and permission failures produce WARN rather than an empty match list.

Match blocks require a connection context and cause WARN for all SSH checks;
there is no claim to calculate effective per-user/per-address configuration.
Malformed/unreadable included content also causes WARN and discards partial
settings. An absent primary configuration is SKIP. Missing explicit directives
are WARN: daemon defaults are not assumed. A PASS is only a static assessment of
an explicit directive, not proof the running daemon uses this file or that the
entire sshd configuration is valid. Unrelated directives are not validated.

Include expansion is bounded to depth 16, 128 file visits, 256 KiB per file and
2 MiB total. Cycles, nonregular files, invalid encoding and exceeded limits yield
WARN. Symlinks are followed to regular files, consistent with normal config use;
this is not a sandbox for untrusted filesystem trees. Concurrent changes are not
an atomic snapshot. No file content or full path is included in error details.

Reference: https://man.openbsd.org/sshd_config (Include, Match, first-value rule).
Connection-specific sshd execution is not implemented. Environment detection and
remaining check families are scheduled for subsequent milestones.

The existing minimum-severity flag now filters results by the effective policy
severity. Internal check errors return CLI exit code 2 even when filtered out; failing
displayed checks return 1,
and other outcomes return 0. WARN/SKIP do not certify compliance.

