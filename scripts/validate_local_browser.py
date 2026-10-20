"""Real Chromium acceptance using synthetic scans; never audit the local host.

Requires the optional Playwright test tool and a Chromium executable. Screenshots
and downloads are written only to the requested (normally ignored) output folder.
"""

import argparse
import json
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

from hardcheck.checks.listeners import LegacyListenerCheck
from hardcheck.local_server import LocalServer, ScanManager


def require(condition, message):
    """Keep acceptance checks active even with optimized Python."""
    if not condition:
        raise RuntimeError(message)


def validate(executable, output):
    from playwright.sync_api import expect, sync_playwright

    output.mkdir(parents=True, exist_ok=True)
    release = threading.Event()
    calls = []
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ("tcp", "tcp6"):
            (root / name).write_text("sl local_address rem_address st\n")
        result = LegacyListenerCheck(root).run()

        def runner():
            calls.append(1)
            if not release.wait(10):
                raise RuntimeError("Synthetic scan timeout")
            if len(calls) == 2:
                raise RuntimeError("Synthetic failure")
            return [result]

        manager = ScanManager(runner, supported=True)
        server = LocalServer(0, "a" * 64, manager)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=executable, headless=True
                )
                context = browser.new_context(viewport={"width": 1440, "height": 1000})
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(server.origin)
                start = page.locator("#real-scan")
                expect(page.locator("#new-scan")).to_be_hidden()
                expect(page.locator("#download")).to_be_disabled()
                expect(start).to_be_enabled()
                expect(page.locator("#local-state")).to_contain_text("Henüz")
                expect(page.locator("#source-tag")).to_have_text("RAPOR BEKLENİYOR")
                start.click()
                expect(start).to_be_disabled()
                expect(page.locator("#local-state")).to_contain_text("Tarama sürüyor")
                second = context.new_page()
                second.goto(server.origin)
                expect(second.locator("#real-scan")).to_be_disabled()
                release.set()
                expect(page.locator("#source-tag")).to_have_text("YEREL TARAMA")
                expect(page.locator("#total")).to_have_text("1")
                expect(page.locator("#passed")).to_have_text("1")
                for identifier in ("failed", "warned", "skipped", "errors"):
                    expect(page.locator("#" + identifier)).to_have_text("0")
                expect(page.locator("#score-coverage")).to_have_text(
                    "1/1 kontrol kesin değerlendirildi · %100 kapsam"
                )
                expect(page.locator("#download")).to_have_text(
                    "↓ Görüntülenen raporu JSON indir"
                )
                page.locator("#findings details summary").click()
                expect(page.locator("#findings")).to_contain_text(
                    "TCP 21 dinleyicisi: 0"
                )
                page.evaluate("window.scrollTo(0, 0)")
                page.screenshot(path=str(output / "desktop.png"), full_page=True)
                for kind in ("json", "html"):
                    with page.expect_download() as download:
                        page.locator("#local-" + kind).click()
                    target = output / ("synthetic-report." + kind)
                    download.value.save_as(target)
                    require(
                        target.read_bytes() == manager.export(kind),
                        "Downloaded bytes differ from the completed scan",
                    )
                require(len(calls) == 1, "Validation failed: len(calls) == 1")
                require(
                    json.loads((output / "synthetic-report.json").read_text())[
                        "findings"
                    ][0]["status"]
                    == "PASS",
                    "Synthetic finding status changed",
                )
                page.set_viewport_size({"width": 390, "height": 844})
                require(
                    page.evaluate("document.documentElement.scrollWidth <= innerWidth"),
                    "Narrow viewport has horizontal overflow",
                )
                page.screenshot(path=str(output / "narrow.png"), full_page=True)
                start.click()
                expect(page.locator("#local-state")).to_contain_text("Tarama başarısız")
                expect(page.locator("#source-tag")).to_have_text("ÖNCEKİ TARAMA")
                expect(page.locator("#local-json")).to_be_disabled()
                start.click()
                expect(page.locator("#report-name")).to_have_text("Yerel tarama #3")
                page.locator('[data-nav="reports"]').click()
                expect(page.locator("#report-list .report-item")).to_have_count(2)
                page.locator("#compare").click()
                expect(page.locator("#comparison-result")).to_contain_text("aynı")
                page.locator("#file").set_input_files(
                    str(output / "synthetic-report.json")
                )
                expect(page.locator("#source-tag")).to_have_text("YÜKLENEN RAPOR")
                page.locator('[data-nav="guide"]').click()
                page.locator("#guide-demo").click()
                expect(page.locator("#scan-dialog")).to_be_visible()
                page.locator("#close-scan").click()
                page.locator('[data-nav="overview"]').click()
                page.locator("#reset").click()
                expect(page.locator("#source-tag")).to_have_text("ÖRNEK RAPOR")
                server.manager = ScanManager(supported=False)
                page.reload()
                expect(start).to_be_disabled()
                expect(page.locator("#local-state")).to_contain_text("yalnızca Linux")
                require(not errors, errors)
                browser.close()
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join()
    print(
        "Chromium: idle/running/completed/error, rescan, two tabs, evidence, "
        "downloads, history, comparison, upload, demo and unsupported platform "
        "passed at 1440px/390px."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    validate(arguments.browser, arguments.output)
