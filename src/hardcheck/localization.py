"""Load bundled translations without changing identifiers or check execution."""

from collections.abc import Mapping
from dataclasses import replace
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType

import yaml

from hardcheck.models import CheckResult, Evidence, EvidenceValue

LANGUAGES = ("en", "tr")


@lru_cache(maxsize=2)
def catalog(language: str = "en") -> Mapping[str, str]:
    """Read trusted package resources; never resolve user-provided resource paths."""
    if language not in LANGUAGES:
        raise ValueError("Unsupported report language")
    resource = files("hardcheck").joinpath("i18n", f"{language}.yaml")
    values = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(values, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value
        for key, value in values.items()
    ):
        raise ValueError("Invalid translation catalog")
    return MappingProxyType(values)


def translate(key: str, language: str = "en") -> str:
    """Use English for a missing translation; missing base keys are errors."""
    values = catalog(language)
    return values[key] if key in values else catalog("en")[key]


def localize_result(result: CheckResult, language: str = "en") -> CheckResult:
    """Translate known guidance while leaving canonical metadata unchanged."""
    values = catalog(language)
    if language == "en":
        return result
    updates = {}
    for field in ("title", "expected", "rationale", "remediation"):
        key = f"checks.{result.check_id}.{field}"
        updates[field] = values.get(key, getattr(result, field))
    return replace(result, **updates)


def evidence_text(fact: Evidence, language: str = "en") -> str:
    """Render validated evidence; retain octal mode notation for human output."""
    label = translate(f"evidence.{fact.key.value}", language)
    if fact.key == "mode_bits" and type(fact.value) is int:
        value = f"{fact.value:04o}"
    elif isinstance(fact.value, EvidenceValue):
        value = translate(f"value.{fact.value.value}", language)
    else:
        value = str(fact.value)
    return f"{label}={value}"


def detail_text(result: CheckResult, language: str = "en") -> str:
    """Translate allowlisted notes; never echo arbitrary probe text to reports."""
    import re

    note, separator, scope = result.detail.partition("; Scope: ")
    if result.detail.startswith("Scope: "):
        note, separator, scope = "", "Scope: ", result.detail[7:]
    parts = []
    if note:
        if f"detail.{note}" in catalog("en"):
            parts.append(translate(f"detail.{note}", language))
        elif re.fullmatch(
            r"World-writable regular files: [0-9]{1,20}; traversal "
            r"(incomplete|complete within declared scope); "
            r"symlinks and special files excluded; ACLs not assessed",
            note,
        ):
            parts.append(translate("world_writable", language))
        else:
            parts.append(translate("fallback_detail", language))
    if separator:
        match = re.fullmatch(
            r"Linux=(True|False), distribution=([a-z0-9._-]{1,64}), "
            r"init=(systemd|openrc|unknown), container=(detected|unknown); "
            r"host namespace unverified",
            scope,
        )
        if match:
            linux, distribution, manager, container = match.groups()
            labels = {
                "linux": translate("environment." + linux.lower(), language),
                "distribution": distribution,
                "init": manager,
                "container": translate("environment." + container, language),
            }
            if distribution == "unknown":
                labels["distribution"] = translate("environment.unknown", language)
            if manager == "unknown":
                labels["init"] = translate("environment.unknown", language)
            parts.append(
                ", ".join(
                    f"{translate('environment.' + key, language)}={value}"
                    for key, value in labels.items()
                )
            )
        parts.append(translate("namespace", language))
    return "; ".join(parts)
