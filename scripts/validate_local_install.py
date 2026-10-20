"""Validate the installed serve entry point and assets from an unrelated cwd.

No scan requests are made. The only terminated process is the child created here.
"""

import http.client
import os
import re
import socket
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory


def require(condition, message):
    """Keep acceptance checks active even with optimized Python."""
    if not condition:
        raise RuntimeError(message)


def validate():
    import hardcheck

    if (
        not Path(hardcheck.__file__)
        .resolve()
        .is_relative_to(Path(sys.prefix).resolve())
    ):
        raise RuntimeError("Use a clean wheel installation without PYTHONPATH")
    binary = Path(sys.executable).parent / "hardcheck"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with TemporaryDirectory(prefix="hardcheck-wheel-") as directory:
        environment = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        environment["XDG_RUNTIME_DIR"] = directory
        process = subprocess.Popen(  # nosec B603
            [str(binary), "serve", "--port", str(port)],
            cwd=directory,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def request(path, headers=None):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                connection.request("GET", path, headers=headers or {})
                response = connection.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()

        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    status, headers, body = request("/")
                    break
                except OSError:
                    if time.monotonic() >= deadline or process.poll() is not None:
                        raise RuntimeError(
                            "Installed serve command did not start"
                        ) from None
                    time.sleep(0.05)
            require(status == 200, "Validation failed: status == 200")
            csrf = re.search(rb'name="hardcheck-csrf" content="([a-f0-9]+)"', body)[
                1
            ].decode()
            for asset in ("app.js", "local.js", "style.css", "demo.json"):
                require(request("/" + asset)[0] == 200, asset)
            credentials = {
                "Cookie": headers["Set-Cookie"].split(";")[0],
                "X-HardCheck-CSRF": csrf,
            }
            require(
                request("/api/status", credentials)[0] == 200,
                "Validation failed: request('/api/status', credentials)[0] == 200",
            )
            require(
                request("/api/status")[0] == 403,
                "Validation failed: request('/api/status')[0] == 403",
            )
            reopened = subprocess.run(  # nosec B603
                [str(binary), "serve", "--port", str(port)],
                cwd=directory,
                env=environment,
                capture_output=True,
                timeout=5,
            )
            require(
                reopened.returncode == 0, "Validation failed: reopened.returncode == 0"
            )
            require(process.poll() is None, "Validation failed: process.poll() is None")
        finally:
            process.terminate()
            process.communicate(timeout=5)
    print("Installed wheel: serve, bundled assets, authenticated API and reuse passed.")


if __name__ == "__main__":
    validate()
