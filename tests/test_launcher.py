"""Exercise private filesystem state and instance ownership without host probes."""

import fcntl
import json
import os
import socket
import threading

import pytest

from hardcheck import cli, desktop, launcher
from hardcheck.local_server import LocalServer, ScanManager


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    return launcher.runtime_directory()


def write_state(runtime, port, key):
    descriptor = launcher.private_open(
        runtime / "session.json", os.O_CREAT | os.O_WRONLY
    )
    with os.fdopen(descriptor, "w") as stream:
        json.dump({"port": port, "key": key}, stream)


def test_private_directory_and_file_permissions(runtime):
    assert runtime.stat().st_mode & 0o777 == 0o700
    descriptor = launcher.private_open(runtime / "lock", os.O_CREAT | os.O_RDWR)
    assert os.fstat(descriptor).st_mode & 0o777 == 0o600
    os.close(descriptor)
    runtime.chmod(0o755)
    with pytest.raises(launcher.LaunchError):
        launcher.runtime_directory()


def test_symlink_and_shared_runtime_files_are_rejected(runtime):
    target = runtime / "target"
    target.write_text("preserve")
    (runtime / "link").symlink_to(target)
    with pytest.raises(OSError):
        launcher.private_open(runtime / "link", os.O_RDWR)
    target.chmod(0o644)
    with pytest.raises(launcher.LaunchError):
        launcher.private_open(target, os.O_RDWR)
    assert target.read_text() == "preserve"


def test_shared_runtime_parent_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    tmp_path.chmod(0o777)
    with pytest.raises(launcher.LaunchError):
        launcher.runtime_directory()
    assert not (tmp_path / "hardcheck").exists()


def test_existing_instance_is_authenticated_and_opened(runtime, monkeypatch):
    key = "a" * 64
    server = LocalServer(0, key, ScanManager(supported=False))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    write_state(runtime, server.server_port, key)
    descriptor = launcher.private_open(
        runtime / "instance.lock", os.O_CREAT | os.O_RDWR
    )
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    opened = []
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    try:
        assert launcher.serve(server.server_port, True) == 0
        assert opened == [server.origin + "/"]
        assert (runtime / "session.json").exists()
        (runtime / "session.json").write_text(
            json.dumps({"port": server.server_port, "key": "b" * 64})
        )
        assert not launcher.verify_instance(runtime, server.server_port)
    finally:
        os.close(descriptor)
        server.shutdown()
        server.server_close()
        thread.join()


def test_port_conflict_is_reported_and_foreign_listener_survives(runtime, capsys):
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", 0))
        foreign.listen()
        port = foreign.getsockname()[1]
        assert launcher.serve(port) == 2
        assert "başka bir uygulamada" in capsys.readouterr().err
        assert foreign.getsockname()[1] == port


def test_stale_state_does_not_prevent_new_owner(runtime, monkeypatch):
    write_state(runtime, 8765, "a" * 64)
    seen = []
    monkeypatch.setattr(
        LocalServer, "serve_forever", lambda self: seen.append(self.origin)
    )
    assert launcher.serve(0) == 0
    assert len(seen) == 1
    assert not (runtime / "session.json").exists()
    # The lock inode stays stable across launches; it is never unlinked.
    inode = (runtime / "instance.lock").stat().st_ino
    assert launcher.serve(0) == 0
    assert (runtime / "instance.lock").stat().st_ino == inode


def test_cli_dispatch_keeps_scan_parser_and_adds_serve(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher, "serve", lambda *args: calls.append(args) or 0)
    assert cli.main(["serve", "--port", "9001", "--open-browser"]) == 0
    assert calls == [(9001, True)]
    assert cli.main(["serve", "--port", "80"]) == 2
    args = cli.build_parser().parse_args(["scan", "--format", "json", "--lang", "tr"])
    assert args.format == "json" and args.lang == "tr"


def test_launcher_uses_venv_python_and_preserves_unmanaged_files(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(desktop.platform, "system", lambda: "Linux")
    monkeypatch.setattr(desktop.sys, "executable", "/tmp/space dir/.venv/bin/python")
    assert cli.main(["install-launcher"]) == 0
    target = tmp_path / "applications/hardcheck.desktop"
    content = target.read_text()
    assert (
        'Exec="/tmp/space dir/.venv/bin/python" -m hardcheck serve --open-browser'
        in content
    )
    assert "Terminal=false" in content
    assert cli.main(["uninstall-launcher"]) == 0
    assert not target.exists()
    target.write_text("custom user launcher")
    assert desktop.install_launcher() == 2
    assert desktop.install_launcher(remove=True) == 2
    assert target.read_text() == "custom user launcher"


def test_desktop_exec_escaping():
    assert desktop.desktop_quote("/tmp/100%/python") == '"/tmp/100%%/python"'
    with pytest.raises(ValueError):
        desktop.desktop_quote("/tmp/injected\nExec=bad")
