"""Strict, versioned scan policy loading; YAML never defines executable checks."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml

from hardcheck.models import Severity
from hardcheck.registry import get_registered_checks
from hardcheck.safe_io import read_regular_text


class ConfigError(ValueError):
    """An invalid or unreadable policy."""


class PolicyLoader(yaml.SafeLoader):
    """Disallow aliases and duplicate keys before schema validation."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ConfigError("YAML aliases are not supported")
        if len(self.compose_stack) >= 12:
            raise ConfigError("YAML nesting limit exceeded")
        self.compose_stack.append(None)
        try:
            return super().compose_node(parent, index)
        finally:
            self.compose_stack.pop()

    def __init__(self, stream):
        self.compose_stack = []
        super().__init__(stream)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ConfigError("Policy keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


@dataclass(frozen=True)
class Rule:
    """Only explicit, typed metadata overrides are permitted."""

    enabled: bool = True
    severity: Severity | None = None


@dataclass(frozen=True)
class Policy:
    """Validated immutable rules for registered check IDs."""

    rules: Mapping[str, Rule]


def load_policy(path: Path) -> Policy:
    """Load schema version 1 with bounded size and strict field validation."""
    try:
        document = yaml.load(read_regular_text(path, 65536), Loader=PolicyLoader)
    except ConfigError:
        raise
    except (OSError, UnicodeError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise ConfigError("Cannot read a valid policy") from exc
    if not isinstance(document, dict) or set(document) != {"version", "checks"}:
        raise ConfigError("Expected only version and checks fields")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ConfigError("Unsupported policy version")
    checks = document["checks"]
    if not isinstance(checks, dict):
        raise ConfigError("checks must be a mapping")
    from hardcheck.checks import ssh as _ssh  # noqa: F401

    known = {check.check_id for check in get_registered_checks()}
    rules = {}
    for identifier, options in checks.items():
        if identifier not in known:
            raise ConfigError("Unknown check identifier")
        if not isinstance(options, dict) or set(options) - {"enabled", "severity"}:
            raise ConfigError("Unknown or invalid check options")
        enabled = options.get("enabled", True)
        if type(enabled) is not bool:
            raise ConfigError("enabled must be a boolean")
        severity = None
        if "severity" in options:
            try:
                severity = Severity(options["severity"])
            except (ValueError, TypeError) as exc:
                raise ConfigError("Invalid severity") from exc
        rules[identifier] = Rule(enabled, severity)
    return Policy(MappingProxyType(rules))
