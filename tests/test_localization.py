"""Catalog parity, complete guidance and stable machine identifiers."""

from dataclasses import asdict

import pytest

from hardcheck.catalog import GUIDANCE
from hardcheck.localization import catalog, evidence_text, localize_result, translate
from hardcheck.models import Evidence, EvidenceKey, Status
from hardcheck.registry import get_registered_checks


def test_catalog_parity_and_complete_guidance():
    en, tr = catalog("en"), catalog("tr")
    assert en.keys() == tr.keys()
    for check_id, guidance in GUIDANCE.items():
        for field, value in asdict(guidance).items():
            key = f"checks.{check_id}.{field}"
            assert en[key] == value
            assert tr[key].strip()
    with pytest.raises(TypeError):
        tr["title"] = "mutated"


def test_translation_does_not_mutate_results_or_identifiers():
    for check in get_registered_checks():
        original = check.result(check, Status.WARN)
        translated = localize_result(original, "tr")
        assert translated.title != original.title
        assert translated.check_id == original.check_id
        assert translated.status == original.status
        assert translated.severity == original.severity
        assert translated.evidence == original.evidence
        assert localize_result(original) is original
        assert original.title == GUIDANCE[check.check_id].title


def test_evidence_labels_and_octal_mode():
    fact = Evidence(EvidenceKey.MODE, 0o640)
    assert evidence_text(fact) == "mode_bits=0640"
    assert evidence_text(fact, "tr") == "izin bitleri=0640"


@pytest.mark.parametrize("language", ["../tr", "", "de", "TR"])
def test_unsupported_language_cannot_select_resource_path(language):
    with pytest.raises(ValueError):
        catalog(language)


def test_missing_translation_falls_back_to_english(monkeypatch):
    import hardcheck.localization as module

    base = catalog("en")
    monkeypatch.setattr(
        module, "catalog", lambda language: {} if language == "tr" else base
    )
    assert translate("title", "tr") == "Title"
    with pytest.raises(KeyError):
        translate("nonexistent", "tr")
