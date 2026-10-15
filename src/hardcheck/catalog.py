"""Human-readable policy explanations; guidance never executes remediation."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class Guidance:
    title: str
    expected: str
    rationale: str
    remediation: str


GUIDANCE = MappingProxyType(
    {
        "SSH-001": Guidance(
            "Disable direct root SSH login",
            "PermitRootLogin no",
            "Direct root login bypasses individual account accountability.",
            "Keep a tested administrative session and recovery access. Review global "
            "and Match settings, disable direct root login, validate with sshd -t, "
            "and test a separate login before any reload.",
        ),
        "SSH-002": Guidance(
            "Disable SSH password authentication",
            "PasswordAuthentication no",
            "Password authentication exposes SSH to password guessing and reuse.",
            "Provision and test an alternative authentication method and recovery "
            "access first. Review PAM/keyboard-interactive paths, validate sshd "
            "configuration and test a separate session before reloading.",
        ),
        "SSH-003": Guidance(
            "Limit SSH authentication attempts",
            "MaxAuthTries between 1 and 4",
            "A per-connection limit reduces repeated authentication attempts.",
            "Review authentication compatibility, set MaxAuthTries to 1–4, validate "
            "with sshd -t and test before reload. This is not a global rate limiter.",
        ),
        "SSH-004": Guidance(
            "Reject empty SSH passwords",
            "PermitEmptyPasswords no",
            "Empty passwords may allow unintended unauthenticated access.",
            "Disable PermitEmptyPasswords, review local account/PAM policy, validate "
            "with sshd -t and verify a separate session before reload.",
        ),
        "USR-001": Guidance(
            "Reject empty local password fields",
            "No empty local shadow password fields",
            "An empty password field can permit passwordless authentication.",
            "Use trusted account-management tools to lock or set credentials for "
            "affected accounts after reviewing service dependencies. Do not expose "
            "shadow content or edit password hashes directly.",
        ),
        "USR-002": Guidance(
            "Restrict UID zero to root",
            "Exactly one UID 0 account named root",
            "Additional UID 0 identities have root-equivalent privileges.",
            "Review privileged identities and file ownership with an administrator; "
            "remove unintended UID 0 assignments using account-management tools. "
            "Preserve recovery access and do not delete accounts blindly.",
        ),
        "USR-003": Guidance(
            "Review password age defaults",
            "Explicit PASS_MAX_DAYS between 1 and 90",
            "Project policy bounds the default password lifetime for new accounts.",
            "Review organizational authentication policy before changing login.defs. "
            "Existing accounts need a separate review; changing this default does "
            "not alter their expiry and is not a universal password policy.",
        ),
        "USR-004": Guidance(
            "Configure minimum password length",
            "Configured length after credits >= 12",
            "Positive character credits can reduce the actual required length.",
            "Review pwquality snippets, positive credits and enforcing; configure "
            "at least 12 actual characters. Verify PAM activation, argument overrides "
            "and root exemptions separately. Existing passwords are not inspected.",
        ),
        "FS-001": Guidance(
            "Protect passwd metadata",
            "Root-owned regular file with mode 0644",
            "Untrusted writers could alter account identities and privilege mappings.",
            "Verify the real target, root ownership, backups and distribution policy "
            "before correcting mode to 0644. Review parent directories and ACLs "
            "separately; do not recursively chmod /etc.",
        ),
        "FS-002": Guidance(
            "Protect shadow metadata",
            "Root-owned regular file; mode subset of 0640",
            "Password hashes require tightly restricted access.",
            "Verify root ownership and a trusted shadow-reader group, then restrict "
            "permissions to the approved subset of 0640. Review ACLs and group "
            "membership separately. Never print or copy hashes into reports.",
        ),
        "FS-003": Guidance(
            "Protect shared temporary entries",
            "Root-owned directory with sticky bit",
            "The sticky bit restricts deletion of other users' directory entries.",
            "Verify /tmp is the intended directory and set the sticky bit while "
            "preserving appropriate access. Review mount policy separately; the "
            "sticky bit alone does not make temporary-file handling secure.",
        ),
        "FS-004": Guidance(
            "Review world-writable configuration files",
            "No world-writable regular files",
            "Unprivileged users may alter security-relevant configuration.",
            "Identify affected paths locally using a trusted tool, verify ownership "
            "and application requirements, then remove unintended world-write "
            "permission individually. Avoid recursive permission changes.",
        ),
        "NET-001": Guidance(
            "Verify active input filtering",
            "Supported active firewall evidence",
            "Active filtering can reduce unintended network exposure.",
            "Review the host firewall and IPv4/IPv6 rules from a recovery-capable "
            "session. Preserve required management access before enabling or "
            "changing filtering. Never flush rules as an automatic fix.",
        ),
        "NET-002": Guidance(
            "Review FTP and telnet listeners",
            "No TCP listeners on ports 21 and 23",
            "Legacy services may expose credentials without transport protection.",
            "Identify listeners and service owners locally; migrate to an approved "
            "encrypted alternative before disabling unnecessary services. Port "
            "numbers alone do not identify a protocol or prove remote reachability.",
        ),
        "NET-003": Guidance(
            "Review IP forwarding",
            "IPv4 and global IPv6 forwarding both equal 0",
            "Unneeded forwarding may allow unintended routing through an endpoint.",
            "Confirm this system is not a router, VPN gateway or container host "
            "requiring forwarding. Only then review live and persistent settings; "
            "evaluate individual IPv6 interface overrides separately.",
        ),
        "KRN-001": Guidance(
            "Enable full address randomization",
            "randomize_va_space = 2",
            "Address randomization can make memory exploitation less predictable.",
            "Check architecture and workload compatibility before enabling full "
            "ASLR and its persistent policy. Verify the live value after changes; "
            "ASLR is not a substitute for memory-safe software.",
        ),
        "KRN-002": Guidance(
            "Restrict kernel log access",
            "dmesg_restrict = 1",
            "Unrestricted kernel logs may disclose security-relevant details.",
            "Review monitoring and operational access requirements, then restrict "
            "unprivileged kernel-log access and verify persistence. Review other "
            "log access paths separately.",
        ),
        "SVC-001": Guidance(
            "Review legacy remote-access software",
            "No known telnet/rsh packages or units",
            "Legacy remote access can expose credentials and weak trust models.",
            "Confirm package/unit ownership and dependencies before disabling or "
            "removing legacy software. Migrate clients first; review custom units, "
            "inetd/xinetd and manually installed programs separately.",
        ),
    }
)
