# Step 4: live network, kernel and service checks

Eighteen fixed built-in checks are registered. No configuration or policy file
can introduce executable checks or arbitrary command arguments. This milestone
adds NET-001–003, KRN-001–002, SVC-001 and best-effort environment labeling.

## Environment boundaries

os-release is read as data, never sourced. Distribution IDs are sanitized. Runtime
directory markers identify systemd/OpenRC when available; missing/denied markers
mean unknown. Docker/Podman/cgroup markers can indicate a container; their absence
never proves bare-metal or host namespace scope. Every result carries environment
scope. Non-Linux scans return SKIP before constructing or executing any control.
The detector is not a container escape, privilege or host-scope verification tool.

## Live controls

- KRN-001: /proc/sys/kernel/randomize_va_space must explicitly equal 2.
- KRN-002: /proc/sys/kernel/dmesg_restrict must explicitly equal 1.
- NET-003: /proc/sys/net/ipv4/ip_forward and the IPv6 global forwarding value
  must both equal 0. Individual IPv6 interface overrides are not enumerated.
  This is a workstation/server assignment policy, not suitable unchanged for a
  router. Missing/denied sources yield SKIP; malformed values yield WARN. Known
  noncompliant values remain FAIL even if another source is unavailable.
- NET-002: both /proc/net/tcp and tcp6 must be readable and parseable; TCP LISTEN
  records on ports 21 or 23 produce FAIL, including loopback listeners. Missing
  tables yield SKIP, malformed records WARN, and known forbidden listeners FAIL
  even with partial visibility. Malformed records mark coverage as uncertain but
  do not stop inspection of later records under a valid table header; a forbidden
  listener before or after a malformed record still yields FAIL.
  UDP, alternate ports, protocol identification,
  remote hosts, other namespaces and hidden/unmounted proc data are not assessed.

All proc results are current-namespace observations, not host-wide or persistent
configuration guarantees. A snapshot can change immediately after inspection.

## Firewall evidence (NET-001)

Supported positive evidence is ufw reporting active, an nftables input filter
base chain with drop policy, or iptables INPUT policy DROP. This detects active
filtering evidence; it does not prove complete IPv4/IPv6 coverage, reachability,
rule ordering or rule effectiveness. Accept-all exceptions can defeat an intended
policy. Complex nftables/iptables rules without recognized positive evidence
produce WARN rather than claiming the firewall is absent. An empty valid ruleset
or inactive supported tool yields FAIL if there is no uncertain source. No tools
available yields SKIP; permissions, invalid output and query failures yield WARN.
A positive supported observation takes precedence over other backend failures.

## Legacy services (SVC-001)

Fixed dpkg-query/RPM inventories are checked for known telnet/rsh client and server
package names, including unpacked Debian packages. systemctl installed and loaded
unit inventories are checked for known telnet/rsh/rlogin/rexec names, including
templates and sockets. Installed disabled legacy units still fail this policy.
PASS requires successful package inventory and both systemd unit inventories with
no known legacy evidence. Malformed individual records do not stop inspection of
later records in that inventory. Any recognized forbidden package/unit yields
FAIL regardless of record order; malformed inventories without such evidence
remain incomplete and cannot establish absence. Partial/unsupported observations
yield WARN; unavailable
queries yield SKIP. Known forbidden evidence yields FAIL despite partial coverage.
OpenRC/inetd/xinetd configurations, renamed or manually installed programs,
containers without a reachable service manager, custom units and external package
systems cannot be certified by this check. Scope is explicitly limited to the
known package/unit inventories; it is not proof of universal service absence.

## Query execution and testing

Queries are fixed allowlisted read-only argument vectors. No shell, caller PATH,
user arguments, inherited environment, sudo or network probing is used. Binaries
come from fixed system directories and must be executable, root-owned regular
files without group/other write bits. Parent-directory trust and replacement races
are not a hardened execution sandbox. Queries have a 3-second deadline and 1 MiB
combined output limit; overrun/error returns no raw output. The process group is
terminated and reaped. Output is parsed internally and excluded from results.

Tests inject proc roots and command results. Runner boundary tests execute only
synthetic Python snippets for output/timeout limits. Integration uses injected
checks and environments, including non-Linux no-execution behavior. No test reads
a real account database, queries a host firewall, or changes system configuration.
GitHub Actions remains manual; local lint/tests are required before commits.

## Primary references

- https://docs.kernel.org/admin-guide/sysctl/kernel.html
- https://docs.kernel.org/networking/ip-sysctl.html
- https://docs.kernel.org/networking/proc_net_tcp.html
- https://www.netfilter.org/projects/nftables/manpage.html
- https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
