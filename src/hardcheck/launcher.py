"""Private Unix runtime lock and authenticated existing-instance discovery."""

import fcntl
import hashlib
import hmac
import http.client
import json
import os
import secrets
import stat
import tempfile
import time
import webbrowser
from pathlib import Path

from hardcheck.local_server import LocalServer

DEFAULT_PORT = 8765


class LaunchError(Exception):
    """A safe, user-facing startup failure."""


def runtime_directory():
    """Keep all runtime files inside a directory private to the current user."""
    base = Path(os.environ.get("XDG_RUNTIME_DIR", Path.home() / ".local/state"))
    if not base.is_absolute():
        raise LaunchError("Çalışma dizini mutlak bir yol olmalı.")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = base.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o022
    ):
        raise LaunchError("Çalışma dizininin üst dizini kullanıcıya özel olmalı.")
    directory = base / "hardcheck"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LaunchError("HardCheck çalışma dizini kullanıcıya ait ve 0700 olmalı.")
    return directory


def private_open(path, flags):
    """Reject symlinks, shared files and objects other than private regular files."""
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise LaunchError("HardCheck oturum dosyasının izinleri güvenli değil.")
    return descriptor


def verify_instance(directory, port):
    """Authenticate a running instance with a fresh challenge, never a PID alone."""
    try:
        with os.fdopen(private_open(directory / "session.json", os.O_RDONLY)) as stream:
            data = json.loads(stream.read(4096))
        if (
            data["port"] != port
            or not isinstance(data["key"], str)
            or len(data["key"]) != 64
        ):
            return False
        challenge = secrets.token_hex(32)
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request(
                "GET", "/api/identity", headers={"X-HardCheck-Challenge": challenge}
            )
            response = connection.getresponse()
            if response.status != 200:
                return False
            proof = json.loads(response.read(4096))["proof"]
            expected = hmac.new(
                data["key"].encode(), challenge.encode(), hashlib.sha256
            ).hexdigest()
            return isinstance(proof, str) and hmac.compare_digest(proof, expected)
        finally:
            connection.close()
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        return False


def show_failure(message):
    """Show launcher failures without needing a terminal or optional GUI toolkit."""
    # Messages come exclusively from fixed strings in this module.
    with tempfile.NamedTemporaryFile(
        mode="w", prefix="hardcheck-error-", suffix=".html", delete=False
    ) as stream:
        stream.write(
            '<!doctype html><html lang="tr"><meta charset="utf-8">'
            "<title>HardCheck başlatılamadı</title><h1>HardCheck başlatılamadı</h1>"
            f"<p>{message}</p><p>Bilinmeyen süreçler durdurulmadı.</p></html>"
        )
    webbrowser.open(Path(stream.name).as_uri())


def serve(port=DEFAULT_PORT, open_browser=False):
    """Hold an OS lock for the server lifetime; reopen only verified instances."""
    descriptor = None
    server = None
    owned = False
    directory = None
    state_written = False
    try:
        if os.getuid() == 0 or os.geteuid() == 0:
            raise LaunchError("HardCheck normal kullanıcı hesabıyla çalıştırılmalı.")
        directory = runtime_directory()
        descriptor = private_open(directory / "instance.lock", os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owned = True
        except BlockingIOError:
            # Allow the lock owner a brief bounded startup window.
            for _ in range(10):
                if verify_instance(directory, port):
                    if open_browser:
                        webbrowser.open(f"http://127.0.0.1:{port}/")
                    return 0
                time.sleep(0.1)
            raise LaunchError(
                "Çalışan HardCheck oturumu doğrulanamadı. "
                "Portu ve oturum dizinini kontrol edin."
            ) from None
        key = secrets.token_hex(32)
        try:
            server = LocalServer(port, key)
        except OSError:
            raise LaunchError(
                f"127.0.0.1:{port} kullanılamıyor. Port başka bir uygulamada olabilir."
            ) from None
        state_fd = private_open(directory / "session.json", os.O_CREAT | os.O_RDWR)
        with os.fdopen(state_fd, "w") as stream:
            stream.truncate(0)
            json.dump({"port": server.server_port, "key": key}, stream)
        state_written = True
        if open_browser:
            webbrowser.open(server.origin + "/")
        print(f"HardCheck: {server.origin}/ (durdurmak için Ctrl+C)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    except (LaunchError, OSError):
        # Avoid logging OS exception paths, probes or credentials.
        import sys

        error = sys.exception()
        message = (
            str(error)
            if isinstance(error, LaunchError)
            else "Yerel servis başlatılamadı."
        )
        print(message, file=sys.stderr)
        if open_browser:
            show_failure(message)
        return 2
    finally:
        if server:
            server.server_close()
        if owned and directory and state_written:
            (directory / "session.json").unlink(missing_ok=True)
        if descriptor is not None:
            os.close(descriptor)
