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


def test_localized_terminal_and_json_keep_exit_codes(monkeypatch, capsys):
    import json

    from hardcheck import cli

    check = get_registered_checks()[0]
    result = check.result(check, Status.FAIL)
    monkeypatch.setattr(cli, "run_checks", lambda _: [result])
    for language, label in [
        ("en", "Manual remediation:"),
        ("tr", "Elle düzeltme önerisi:"),
    ]:
        assert cli.main(["scan", "--lang", language, "--explain"]) == 1
        terminal = capsys.readouterr().out
        assert label in terminal
        assert f"{result.check_id}: FAIL" in terminal
        assert cli.main(["scan", "--lang", language, "--format", "json"]) == 1
        report = json.loads(capsys.readouterr().out)
        assert report["language"] == language
        assert report["findings"][0]["check_id"] == result.check_id
        assert report["findings"][0]["status"] == "FAIL"
        assert report["summary"]["score_percent"] == 0
        assert report["findings"][0]["title"] in terminal


def test_diagnostics_use_selected_language(tmp_path, monkeypatch, capsys):
    from hardcheck import cli

    def forbidden(*args):
        raise AssertionError("Invalid configuration must not scan")

    monkeypatch.setattr(cli, "run_checks", forbidden)
    assert cli.main(["scan", "--lang", "tr", "--output", ""]) == 2
    assert "boş olamaz" in capsys.readouterr().err
    assert (
        cli.main(["scan", "--lang", "tr", "--config", str(tmp_path / "missing")]) == 2
    )
    captured = capsys.readouterr()
    assert "Geçersiz yapılandırma" in captured.err
    assert not captured.out


def test_safe_note_translates_scope_without_echoing_arbitrary_detail():
    from dataclasses import replace

    from hardcheck.localization import detail_text

    check = get_registered_checks()[0]
    original = check.result(
        check,
        Status.WARN,
        "Local account file is empty; Scope: Linux=True, distribution=debian, "
        "init=unknown, container=detected; host namespace unverified",
    )
    translated = detail_text(original, "tr")
    assert "Yerel hesap dosyası boş" in translated
    assert "dağıtım=debian" in translated
    assert "tespit edildi" in translated
    assert "ana sistem ad alanı doğrulanmadı" in translated
    hostile = replace(original, detail="private-secret\x1b[31m<script>")
    assert "private-secret" not in detail_text(hostile)
    assert "<script>" not in detail_text(hostile, "tr")
