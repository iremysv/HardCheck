"""Exercise real HTTP boundaries with synthetic checks, never scan the host."""

import hashlib
import hmac
import http.client
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from hardcheck.checks.listeners import LegacyListenerCheck
from hardcheck.local_server import LocalServer, ScanManager


def wait_for(manager, state):
    deadline = time.monotonic() + 3
    while manager.snapshot()["state"] != state and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.snapshot()["state"] == state


@pytest.fixture
def result(tmp_path):
    for name in ("tcp", "tcp6"):
        (tmp_path / name).write_text("sl local_address rem_address st\n")
    return LegacyListenerCheck(tmp_path).run()


@pytest.fixture
def service(result):
    manager = ScanManager(lambda: [result], supported=True)
    server = LocalServer(0, "a" * 64, manager)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


def request(server, path="/", method="GET", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def auth(server):
    status, headers, body = request(server)
    assert status == 200
    token = re.search(rb'name="hardcheck-csrf" content="([a-f0-9]+)"', body)[1].decode()
    assert "HttpOnly; SameSite=Strict" in headers["Set-Cookie"]
    return {
        "Cookie": headers["Set-Cookie"].split(";")[0],
        "X-HardCheck-CSRF": token,
        "Origin": server.origin,
    }


@pytest.mark.parametrize(
    "host", ["localhost", "localhost:8765", "127.0.0.1", "evil.test", "127.0.0.1:1"]
)
def test_exact_host_required(service, host):
    assert request(service, headers={"Host": host})[0] == 403


@pytest.mark.parametrize(
    "origin",
    [
        "null",
        "http://evil.test",
        "http://localhost:8765",
        "http://127.0.0.1:1",
        "https://127.0.0.1:8765",
    ],
)
def test_exact_origin_required(service, origin):
    assert request(service, headers={"Origin": origin})[0] == 403


def test_cross_site_navigation_and_rebinding_are_denied(service):
    assert request(service, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert request(service, headers={"Sec-Fetch-Site": "same-site"})[0] == 403
    assert request(service, headers={"Sec-Fetch-Site": "none"})[0] == 200
    assert request(service, "/?token=not-allowed")[0] == 404
    assert request(service, "/../pyproject.toml")[0] == 404


def test_api_requires_cookie_and_csrf_and_post_origin(service):
    headers = auth(service)
    assert request(service, "/api/status")[0] == 403
    for missing in ("Cookie", "X-HardCheck-CSRF", "Origin"):
        incomplete = {k: v for k, v in headers.items() if k != missing}
        assert request(service, "/api/scan", "POST", incomplete)[0] == 403
    assert request(service, "/api/scan", headers=headers)[0] == 404
    assert request(service, "/api/scan", "OPTIONS", headers)[0] == 501
    invalid = {**headers, "Content-Length": "1"}
    assert request(service, "/api/scan", "POST", invalid)[0] == 400
    assert service.manager.snapshot()["state"] == "idle"


def test_get_without_origin_downloads_one_completed_result(service):
    headers = auth(service)
    calls = []
    original = service.manager.runner
    service.manager.runner = lambda: calls.append(1) or original()
    assert request(service, "/api/report.json", headers=headers)[0] == 409
    assert request(service, "/api/scan", "POST", headers)[0] == 202
    wait_for(service.manager, "completed")
    headers.pop("Origin")
    for kind in ("json", "html"):
        status, response_headers, body = request(
            service, "/api/report." + kind, headers=headers
        )
        assert status == 200
        assert "attachment" in response_headers["Content-Disposition"]
        assert "Access-Control-Allow-Origin" not in response_headers
        assert response_headers["Cache-Control"] == "no-store"
        assert body == service.manager.export(kind)
    assert json.loads(service.manager.export("json"))["findings"][0]["status"] == "PASS"
    assert calls == [1]


def test_concurrent_scan_rejected_without_waiting(service):
    started, release = threading.Event(), threading.Event()

    def blocked():
        started.set()
        assert release.wait(3)
        return []

    service.manager.runner = blocked
    headers = auth(service)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(request, service, "/api/scan", "POST", headers)
                for _ in range(2)
            ]
            statuses = sorted(f.result(timeout=1)[0] for f in futures)
        assert statuses == [202, 409]
        assert started.wait(1)
        assert service.manager.snapshot()["state"] == "running"
        assert request(service, "/api/report.json", headers=headers)[0] == 409
    finally:
        release.set()
    wait_for(service.manager, "completed")


def test_failed_rescan_discards_old_exports_and_releases_admission(service):
    headers = auth(service)
    request(service, "/api/scan", "POST", headers)
    wait_for(service.manager, "completed")

    def broken():
        raise RuntimeError("secret exception text")

    service.manager.runner = broken
    assert request(service, "/api/scan", "POST", headers)[0] == 202
    wait_for(service.manager, "error")
    assert request(service, "/api/report.html", headers=headers)[0] == 409
    state = request(service, "/api/status", headers=headers)[2]
    assert b"secret" not in state
    service.manager.runner = lambda: []
    assert request(service, "/api/scan", "POST", headers)[0] == 202
    wait_for(service.manager, "completed")
    assert service.manager.snapshot()["generation"] == 3
    assert json.loads(service.manager.export("json"))["findings"] == []


def test_render_failure_is_not_a_completed_scan(service, monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("private")

    monkeypatch.setattr("hardcheck.local_server.html_report", broken)
    assert service.manager.start() == 202
    wait_for(service.manager, "error")
    assert service.manager.export("json") is None


def test_worker_start_failure_allows_retry(service, monkeypatch):
    def broken_start(self):
        raise RuntimeError("private thread failure")

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", broken_start)
        assert service.manager.start() == 500
    assert service.manager.snapshot()["state"] == "error"
    assert service.manager.start() == 202
    wait_for(service.manager, "completed")


def test_unsupported_platform_never_calls_engine(service):
    service.manager.supported = False
    assert request(service, "/api/scan", "POST", auth(service))[0] == 422
    assert service.manager.snapshot()["state"] == "idle"


def test_identity_proof_is_bound_to_a_fresh_challenge(service):
    challenge = "b" * 64
    status, _, body = request(
        service, "/api/identity", headers={"X-HardCheck-Challenge": challenge}
    )
    assert status == 200
    assert (
        json.loads(body)["proof"]
        == hmac.new(b"a" * 64, challenge.encode(), hashlib.sha256).hexdigest()
    )
    assert service.csrf.encode() not in body
    assert service.session.encode() not in body
    assert request(service, "/api/identity")[0] == 403


def test_duplicate_host_and_origin_headers_are_rejected(service):
    for name, value in (("Host", service.authority), ("Origin", service.origin)):
        connection = http.client.HTTPConnection("127.0.0.1", service.server_port)
        connection.putrequest("GET", "/", skip_host=True)
        connection.putheader("Host", service.authority)
        if name == "Origin":
            connection.putheader("Origin", service.origin)
        connection.putheader(name, value)
        connection.endheaders()
        assert connection.getresponse().status == 403
        connection.close()


@pytest.mark.parametrize("method", ["PUT", "DELETE", "TRACE", "HEAD"])
def test_unsupported_methods_have_private_hardened_errors(service, method):
    status, headers, body = request(service, method=method)
    assert status == 501
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert body == b""
