"""Identify installed legacy packages and systemd units through fixed queries."""

import re

from hardcheck.checks.base import BaseCheck
from hardcheck.commands import run_query
from hardcheck.models import (
    CheckResult,
    Evidence,
    EvidenceKey,
    EvidenceValue,
    Severity,
    Status,
)

LEGACY_PACKAGES = {
    "telnet",
    "telnetd",
    "telnet-server",
    "inetutils-telnet",
    "inetutils-telnetd",
    "rsh",
    "rsh-server",
    "rsh-client",
    "rsh-redone-client",
    "rsh-redone-server",
}
LEGACY_UNITS = {
    "telnet",
    "telnetd",
    "rsh",
    "rshd",
    "rlogin",
    "rlogind",
    "rexec",
    "rexecd",
    "in.telnetd",
    "in.rshd",
    "in.rlogind",
    "in.rexecd",
}


def legacy_package(line: str, query: str) -> bool:
    """Parse one package record without exposing names in public evidence."""
    if query == "packages-deb":
        name, state = line.split("\t")
        name = name.split(":", 1)[0]
        if state not in {
            "installed", "not-installed", "config-files", "unpacked",
            "half-installed", "half-configured", "triggers-awaited", "triggers-pending",
        }:
            raise ValueError("Invalid package state")
        # Unconfigured legacy packages remain a finding.
        installed = state not in {"not-installed", "config-files"}
    else:
        name = line
        installed = True
    if not re.fullmatch(r"[A-Za-z0-9.+_-]+", name):
        raise ValueError("Invalid package name")
    return name in LEGACY_PACKAGES and installed


def legacy_unit(line: str) -> bool:
    """Parse one unit record, including template and socket names."""
    fields = line.split()
    if len(fields) < 2 or "." not in fields[0]:
        raise ValueError("Invalid unit record")
    name = fields[0].rsplit(".", 1)[0].split("@", 1)[0]
    return name in LEGACY_UNITS


class LegacyServiceCheck(BaseCheck):
    check_id = "SVC-001"
    category = "services"
    severity = Severity.HIGH
    reference = "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html"

    def run(self) -> CheckResult:
        package_observed = False
        units_observed = 0
        uncertain = False
        for query in ("packages-deb", "packages-rpm", "unit-files", "units"):
            response = run_query(query)
            if response.state == "missing":
                continue
            if response.state != "done" or response.code != 0:
                uncertain = True
                continue
            packages = query.startswith("packages-")
            lines = response.output.splitlines()
            valid_inventory = bool(lines) if packages else True
            for line in lines:
                try:
                    found = (
                        legacy_package(line, query) if packages else legacy_unit(line)
                    )
                except ValueError:
                    valid_inventory = False
                    continue
                if found:
                    key = EvidenceKey.PACKAGE if packages else EvidenceKey.UNIT
                    return self.result(
                        Status.FAIL,
                        "Legacy package detected"
                        if packages else "Legacy unit detected",
                        evidence=(Evidence(key, EvidenceValue.PRESENT),),
                    )
            if not valid_inventory:
                uncertain = True
            elif packages:
                package_observed = True
            else:
                units_observed += 1
        complete = package_observed and units_observed == 2 and not uncertain
        status = Status.PASS if complete else Status.WARN
        if not package_observed and not units_observed and not uncertain:
            status = Status.SKIP
        return self.result(
            status,
            "Known package/unit names only; custom binaries and inetd definitions "
            "not assessed; current environment only",
            evidence=(
                Evidence(
                    EvidenceKey.PACKAGE,
                    EvidenceValue.ABSENT if package_observed else EvidenceValue.UNKNOWN,
                ),
                Evidence(
                    EvidenceKey.UNIT,
                    EvidenceValue.ABSENT
                    if units_observed == 2
                    else EvidenceValue.UNKNOWN,
                ),
                Evidence(
                    EvidenceKey.COVERAGE,
                    EvidenceValue.COMPLETE if complete else EvidenceValue.PARTIAL,
                ),
            ),
        )
