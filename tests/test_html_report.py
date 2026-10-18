"""HTML escaping, URL safety, offline assets and score/scope parity."""

import base64
import hashlib
from dataclasses import replace
from html.parser import HTMLParser

import pytest

from hardcheck.models import Severity, Status
from hardcheck.registry import get_registered_checks
from hardcheck.reports.html import html_report, reference_url


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def result(status=Status.WARN):
    check = get_registered_checks()[0]
    return check.result(check, status)


@pytest.mark.parametrize("language", ["en", "tr"])
def test_html_report_language_scope_and_offline_assets(language):
    findings = [result(status) for status in Status]
    report = html_report(findings, findings, language=language)
    document = Document(report)
    assert ("html", {"lang": language}) in document.tags
    assert "50.0%" in report and "40.0%" in report
    assert "2/5" in report
    assert "WARN" in report and "SKIP" in report
    assert "<script" not in report
    for tag, attributes in document.tags:
        assert tag not in {"script", "iframe", "object", "embed", "img", "link", "form"}
        assert not any(key.startswith("on") for key in attributes)
        assert "src" not in attributes and "srcset" not in attributes
    if language == "tr":
        assert "HardCheck güvenlik raporu" in report
        assert "ana sistem ad alanı doğrulanmadı" in report
    style = report.split("<style>", 1)[1].split("</style>", 1)[0]
    digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in report
    assert "script-src 'none'" in report


def test_all_dynamic_html_text_is_escaped():
    payload = '</style><script>alert("x")</script><img src=x onerror=alert(1)>'
    finding = replace(
        result(),
        check_id=payload,
        title=payload,
        expected=payload,
        rationale=payload,
        remediation=payload,
        category=payload,
        reference=payload,
        detail=payload,
    )
    report = html_report([finding], [finding])
    assert payload not in report
    assert "&lt;script&gt;" in report
    assert not any(tag in {"script", "img"} for tag, _ in Document(report).tags)
    assert not any("onerror" in attrs for _, attrs in Document(report).tags)
    assert all(attrs.get("href") != payload for _, attrs in Document(report).tags)


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,hi",
        "//example.org",
        "http://example.org",
        # Deliberately invalid URL credentials exercise link rejection.
        "https://user:pass@example.org",  # pragma: allowlist secret
        "https://example.org\n.evil",
        "https://[invalid",
        "https://example.org\\@evil.org",
        "https://",
    ],
)
def test_unsafe_reference_links_are_not_clickable(url):
    assert reference_url(url) is None
    finding = replace(result(), reference=url)
    assert not any(
        "href" in attrs for _, attrs in Document(html_report([finding], [finding])).tags
    )


def test_https_reference_attribute_is_escaped():
    url = 'https://example.org/?q="onmouseover="alert(1)&x=<script>'
    finding = replace(result(), reference=url)
    report = html_report([finding], [finding])
    links = [attrs for tag, attrs in Document(report).tags if tag == "a"]
    assert len(links) == 1
    assert links[0]["href"] == url
    assert "onmouseover" not in links[0]
    assert "noopener" in links[0]["rel"]


def test_empty_selection_and_hidden_errors_are_explicit():
    hidden = replace(result(Status.ERROR), severity=Severity.LOW)
    report = html_report([], [hidden], "critical", "tr")
    assert "Kontrol seçilmedi" in report
    assert "Hesaplanamadı" in report
    assert "tarama ERROR=1" in report
    assert "<dd>100" not in report
