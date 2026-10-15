"""Firewall queries are mocked; no host firewall is read or modified."""

import json

import pytest

from hardcheck.checks import firewall
from hardcheck.commands import CommandResult
from hardcheck.models import Status


@pytest.mark.parametrize(
    ("query", "output", "status"),
    [
        ("ufw", "Status: active\n", Status.PASS),
        ("ufw", "Status: inactive\n", Status.FAIL),
        ("iptables", "-P INPUT DROP\n", Status.PASS),
        ("iptables", "-P INPUT ACCEPT\n", Status.FAIL),
        ("nft", '{"nftables": []}', Status.FAIL),
        ("nft", "not-json", Status.WARN),
    ],
)
def test_firewall_queries(monkeypatch, query, output, status):
    monkeypatch.setattr(
        firewall,
        "run_query",
        lambda name: (
            CommandResult("done", output, 0)
            if name == query
            else CommandResult("missing")
        ),
    )
    assert firewall.FirewallCheck().run().status == status


def test_nft_base_chain_and_unavailable(monkeypatch):
    output = json.dumps(
        {
            "nftables": [
                {
                    "chain": {
                        "type": "filter",
                        "hook": "input",
                        "family": "inet",
                        "policy": "drop",
                    }
                }
            ]
        }
    )
    monkeypatch.setattr(
        firewall,
        "run_query",
        lambda name: (
            CommandResult("done", output, 0)
            if name == "nft"
            else CommandResult("missing")
        ),
    )
    assert firewall.FirewallCheck().run().status == Status.PASS
    monkeypatch.setattr(firewall, "run_query", lambda name: CommandResult("missing"))
    assert firewall.FirewallCheck().run().status == Status.SKIP
    monkeypatch.setattr(
        firewall, "run_query", lambda name: CommandResult("done", "", 1)
    )
    assert firewall.FirewallCheck().run().status == Status.WARN
