"""Review synthetic offline reports with optional Playwright/Chromium tooling."""

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path


def validate(output: Path, executable: Path | None = None) -> None:
    from playwright.sync_api import sync_playwright

    from hardcheck.models import Status
    from hardcheck.registry import get_registered_checks
    from hardcheck.reports.html import html_report

    output.mkdir(mode=0o700)
    findings = [
        check.result(check, list(Status)[index % len(Status)])
        for index, check in enumerate(get_registered_checks())
    ]
    long = replace(
        findings[0],
        check_id="SYNTHETIC-LONG",
        title="Çığ, şüphe ve uzun başlık " + "ABC" * 100,
        remediation="Synthetic manual review guidance. " * 200,
    )
    cases = {"full": findings, "empty": [], "long": [long]}
    results = []
    failures = []
    with sync_playwright() as playwright:
        options = {"headless": True}
        if executable is not None:
            options["executable_path"] = str(executable)
        browser = playwright.chromium.launch(**options)
        browser_version = browser.version
        for language in ("en", "tr"):
            for case, selected in cases.items():
                path = output / f"{case}-{language}.html"
                path.write_text(
                    html_report(
                        selected,
                        findings if case == "empty" else selected,
                        language=language,
                    ),
                    encoding="utf-8",
                )
                for media, width, height in (
                    ("desktop", 1280, 1000),
                    ("mobile", 390, 844),
                    ("print", 794, 1123),
                ):
                    requests = []
                    errors = []
                    context = browser.new_context(
                        viewport={"width": width, "height": height}
                    )

                    def route_request(route, requests=requests):
                        if route.request.url.startswith(("https:", "http:")):
                            requests.append(route.request.url)
                            route.abort()
                        else:
                            route.continue_()

                    context.route("**/*", route_request)
                    page = context.new_page()
                    page.on(
                        "pageerror",
                        lambda error, errors=errors: errors.append(str(error)),
                    )
                    if media == "print":
                        page.emulate_media(media="print")
                    page.goto(path.resolve().as_uri())
                    geometry = page.evaluate("""() => ({
                        width: innerWidth, scroll: document.documentElement.scrollWidth,
                        sections: document.querySelectorAll('.finding').length,
                        language: document.documentElement.lang
                    })""")
                    name = f"{case}-{language}-{media}"
                    page.screenshot(path=str(output / f"{name}.png"))
                    if selected and media != "print":
                        page.locator(".finding").first.screenshot(
                            path=str(output / f"{name}-finding.png")
                        )
                    passed = (
                        geometry["scroll"] <= width
                        and geometry["sections"] == len(selected)
                        and geometry["language"] == language
                        and not requests
                        and not errors
                    )
                    results.append(
                        {
                            "case": name,
                            **geometry,
                            "external_requests": len(requests),
                            "page_errors": len(errors),
                            "passed": passed,
                        }
                    )
                    if not passed:
                        failures.append(name)
                    context.close()
        browser.close()
    (output / "results.json").write_text(
        json.dumps({"browser": browser_version, "cases": results}, indent=2),
        encoding="utf-8",
    )
    if failures:
        raise ValueError("HTML layout validation failed: " + ", ".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="NEW screenshot directory"
    )
    parser.add_argument(
        "--browser", type=Path, help="Optional existing Chromium executable"
    )
    arguments = parser.parse_args()
    try:
        validate(arguments.output, arguments.browser)
    except ImportError:
        print("Install Playwright and its Chromium browser first.", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        "HTML layout validation passed: "
        "18 desktop/mobile/print cases; no external requests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
