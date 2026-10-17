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
