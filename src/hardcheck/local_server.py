"""Loopback-only panel and a single, read-only scan manager."""

import hashlib
import hmac
import json
import platform
import re
import secrets
import threading
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path

from hardcheck.engine import run_checks
from hardcheck.reporting import json_report
from hardcheck.reports.html import html_report


class ScanManager:
    """Own scan admission and publish both exports atomically."""

    def __init__(self, runner=run_checks, supported=None):
        self.runner = runner
        self.supported = (
            platform.system() == "Linux" if supported is None else supported
        )
        self.lock = threading.Lock()
        self.state = "idle"
        self.generation = 0
        self.exports = None
        self.error = None

    def snapshot(self):
        with self.lock:
            return {
                "state": self.state,
                "generation": self.generation,
                "supported": self.supported,
                "error": self.error,
            }

    def start(self):
        with self.lock:
            if self.state == "running":
                return 409
            if not self.supported:
                return 422
            self.state, self.error, self.exports = "running", None, None
            self.generation += 1
            try:
                threading.Thread(target=self._run, daemon=True).start()
            except Exception:
                self.state = "error"
                self.error = "Tarama başlatılamadı. Yeniden deneyin."
                return 500
        return 202

    def _run(self):
        try:
            results = self.runner()
            exports = {
                "json": json_report(results, results, language="tr").encode(),
                "html": html_report(results, results, language="tr").encode(),
            }
        except Exception:
            # Never expose exception text, raw probes or local paths.
            with self.lock:
                self.state = "error"
                self.error = "Tarama veya rapor üretimi tamamlanamadı. Yeniden deneyin."
            return
        with self.lock:
            self.exports = exports
            self.state = "completed"

    def export(self, kind):
        with self.lock:
            return self.exports[kind] if self.state == "completed" else None


def panel_asset(name):
    """Resolve installed wheel resources, or the editable source tree."""
    resource = files("hardcheck").joinpath("web", name)
    if resource.is_file():
        return resource.read_bytes()
    return (Path(__file__).resolve().parents[2] / "web" / "dist" / name).read_bytes()


class LocalServer(ThreadingHTTPServer):
    """HTTP transport restricted to an exact loopback authority."""

    daemon_threads = True
    # Reclaim our TIME_WAIT address after exit, never share an active listener.
    allow_reuse_address = True
    allow_reuse_port = False

    def __init__(self, port, identity_key, manager=None):
        self.manager = manager if manager is not None else ScanManager()
        self.identity_key = identity_key
        self.session = secrets.token_hex(32)
        self.csrf = secrets.token_hex(32)
        super().__init__(("127.0.0.1", port), Handler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.authority
        self.cookie_name = f"hardcheck_{self.server_port}"

    def handle_error(self, request, client_address):
        """Do not log request data or private exception details."""


class Handler(BaseHTTPRequestHandler):
    """Serve allowlisted assets and authenticated, same-origin API requests."""

    server_version = "HardCheck"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        """Request URLs, headers and tokens must never enter logs."""

    def respond(
        self, code, body=b"", mime="application/json", *, cookie=False, download=None
    ):
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        if cookie:
            self.send_header(
                "Set-Cookie",
                f"{self.server.cookie_name}="
                f"{self.server.session}; HttpOnly; SameSite=Strict; Path=/",
            )
        if download:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{download}"'
            )
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        """Apply the same headers to parser errors and unsupported methods."""
        self.respond(code)

    def guard(self):
        if self.headers.get_all("Host") != [self.server.authority]:
            self.respond(403)
            return False
        origins = self.headers.get_all("Origin")
        if origins is not None and origins != [self.server.origin]:
            self.respond(403)
            return False
        sites = self.headers.get_all("Sec-Fetch-Site")
        if sites is not None and sites not in (["same-origin"], ["none"]):
            self.respond(403)
            return False
        if "?" in self.path or "#" in self.path:
            self.respond(404)
            return False
        return True

    def authenticated(self, csrf=True):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            value = cookie[self.server.cookie_name].value
        except (CookieError, KeyError, ValueError):
            value = ""
        valid = hmac.compare_digest(value.encode(), self.server.session.encode())
        if csrf:
            valid = valid and self.headers.get_all("X-HardCheck-CSRF") == [
                self.server.csrf
            ]
        if not valid:
            self.respond(403)
        return valid

    def do_GET(self):
        if not self.guard():
            return
        if self.path == "/api/identity":
            challenge = self.headers.get("X-HardCheck-Challenge", "")
            if not re.fullmatch(r"[a-f0-9]{64}", challenge):
                self.respond(403)
                return
            proof = hmac.new(
                self.server.identity_key.encode(), challenge.encode(), hashlib.sha256
            ).hexdigest()
            self.respond(200, json.dumps({"proof": proof}).encode())
        elif self.path in ("/", "/index.html"):
            html = panel_asset("index.html").replace(
                b"<!-- LOCAL_SESSION -->",
                f'<meta name="hardcheck-csrf" content="{self.server.csrf}">'.encode(),
            )
            self.respond(200, html, "text/html; charset=utf-8", cookie=True)
        elif self.path in ("/app.js", "/local.js", "/style.css", "/demo.json"):
            mime = {
                "js": "text/javascript",
                "css": "text/css",
                "json": "application/json",
            }
            self.respond(
                200,
                panel_asset(self.path[1:]),
                mime[self.path.rsplit(".", 1)[1]] + "; charset=utf-8",
            )
        elif self.path == "/api/status":
            if self.authenticated():
                self.respond(200, json.dumps(self.server.manager.snapshot()).encode())
        elif self.path in ("/api/report.json", "/api/report.html"):
            if not self.authenticated(csrf=False):
                return
            kind = self.path.rsplit(".", 1)[1]
            body = self.server.manager.export(kind)
            if body is None:
                self.respond(409)
                return
            self.respond(
                200,
                body,
                "application/json" if kind == "json" else "text/html",
                download="hardcheck-report." + kind,
            )
        else:
            self.respond(404)

    def do_POST(self):
        if not self.guard() or not self.authenticated():
            return
        if self.headers.get_all("Origin") != [self.server.origin]:
            self.respond(403)
            return
        if (
            self.headers.get_all("Content-Length") != ["0"]
            or "Transfer-Encoding" in self.headers
        ):
            self.respond(400)
            return
        if self.path != "/api/scan":
            self.respond(404)
            return
        self.respond(self.server.manager.start())
