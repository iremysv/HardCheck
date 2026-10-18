"""The installed-artifact validator refuses source imports before any probes."""

import pytest

from scripts import validate_install


def test_validator_rejects_source_checkout_without_creating_reports(
    tmp_path, monkeypatch
):
    import hardcheck
    from hardcheck import registry

    monkeypatch.setattr(hardcheck, "__file__", str(tmp_path / "source" / "__init__.py"))

    def forbidden():
        raise AssertionError("Source validation must stop before loading checks")

    monkeypatch.setattr(registry, "get_registered_checks", forbidden)
    reports = tmp_path / "reports"
    with pytest.raises(validate_install.ValidationError, match="installed artifact"):
        validate_install.validate(reports)
    assert not reports.exists()
