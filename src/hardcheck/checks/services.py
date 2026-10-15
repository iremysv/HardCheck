"""Identify installed legacy packages and systemd units through fixed queries."""

import re

from hardcheck.checks.base import BaseCheck
from hardcheck.commands import run_query
from hardcheck.models import CheckResult, Severity, Status

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
            try:
                lines = response.output.splitlines()
                if query.startswith("packages-"):
                    if not lines:
                        raise ValueError
                    for line in lines:
                        if query == "packages-deb":
                            name, state = line.split("\t")
                            name = name.split(":", 1)[0]
                            installed = state == "installed"
                            if state not in {
                                "installed",
                                "not-installed",
                                "config-files",
                                "unpacked",
                                "half-installed",
                                "half-configured",
                                "triggers-awaited",
                                "triggers-pending",
                            }:
                                raise ValueError
                            # Unconfigured legacy packages remain a finding.
                            installed = state not in {"not-installed", "config-files"}
                        else:
                            name = line
                            installed = True
                        if not re.fullmatch(r"[A-Za-z0-9.+_-]+", name):
                            raise ValueError
                        if name in LEGACY_PACKAGES and installed:
                            return self.result(Status.FAIL, "Legacy package detected")
                    package_observed = True
                else:
                    for line in lines:
                        fields = line.split()
                        if len(fields) < 2 or "." not in fields[0]:
                            raise ValueError
                        name = fields[0].rsplit(".", 1)[0].split("@", 1)[0]
                        if name in LEGACY_UNITS:
                            return self.result(Status.FAIL, "Legacy unit detected")
                    units_observed += 1
            except ValueError:
                uncertain = True
        complete = package_observed and units_observed == 2 and not uncertain
        status = Status.PASS if complete else Status.WARN
        if not package_observed and not units_observed and not uncertain:
            status = Status.SKIP
        return self.result(
            status,
            "Known package/unit names only; custom binaries and inetd definitions "
            "not assessed; current environment only",
        )
