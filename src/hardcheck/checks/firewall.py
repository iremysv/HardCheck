"""Conservative evidence of active input filtering, not firewall effectiveness."""

import json

from hardcheck.checks.base import BaseCheck
from hardcheck.commands import run_query
from hardcheck.models import CheckResult, Severity, Status


class FirewallCheck(BaseCheck):
    check_id = "NET-001"
    category = "network"
    severity = Severity.HIGH
    reference = "https://www.netfilter.org/projects/nftables/manpage.html"

    def run(self) -> CheckResult:
        observed = False
        uncertain = False
        for query in ("ufw", "nft", "iptables"):
            response = run_query(query)
            if response.state == "missing":
                continue
            if response.state != "done" or response.code != 0:
                uncertain = True
                continue
            observed = True
            active = False
            try:
                if query == "ufw":
                    lines = response.output.splitlines()
                    active = bool(lines and lines[0].strip() == "Status: active")
                    if not active and not (
                        lines and lines[0].strip() == "Status: inactive"
                    ):
                        uncertain = True
                elif query == "nft":
                    document = json.loads(response.output)
                    items = document["nftables"]
                    if not isinstance(items, list):
                        raise ValueError
                    if any(isinstance(item, dict) and "rule" in item for item in items):
                        uncertain = True
                    for item in items:
                        chain = item.get("chain", {})
                        if (
                            chain.get("type") == "filter"
                            and chain.get("hook") == "input"
                            and chain.get("family") in {"ip", "ip6", "inet"}
                            and chain.get("policy") == "drop"
                        ):
                            active = True
                else:
                    lines = response.output.splitlines()
                    active = "-P INPUT DROP" in lines
                    if any(line.startswith("-A INPUT ") for line in lines):
                        uncertain = True
                    if not any(line.startswith("-P INPUT ") for line in lines):
                        uncertain = True
                if active:
                    return self.result(
                        Status.PASS,
                        "Input filtering evidence; rule effectiveness and all families "
                        "not proven; current namespace only",
                    )
            except (ValueError, KeyError, TypeError, AttributeError):
                uncertain = True
        status = Status.WARN if uncertain else Status.FAIL if observed else Status.SKIP
        return self.result(status, "No verified active supported firewall evidence")
