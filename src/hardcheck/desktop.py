"""Install a per-user Linux application entry without privileged services."""

import os
import platform
import stat
import sys
from pathlib import Path

MARKER = "X-HardCheck-Managed=true"


def desktop_quote(value):
    """Escape a desktop Exec argument (not a shell command)."""
    if any(char in value for char in "\n\r\x00"):
        raise ValueError("Invalid executable path")
    value = value.replace("%", "%%")
    for char in ("\\", '"', "`", "$"):
        value = value.replace(char, "\\" + char)
    # Desktop string parsing precedes Exec argument parsing.
    return '"' + value.replace("\\", "\\\\") + '"'


def install_launcher(remove=False):
    """Create or remove only our managed application-menu entry."""
    if platform.system() != "Linux" or os.getuid() == 0 or os.geteuid() == 0:
        print("Başlatıcı normal Linux kullanıcısı için desteklenir.", file=sys.stderr)
        return 2
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    if not base.is_absolute():
        print("XDG_DATA_HOME mutlak bir yol olmalı.", file=sys.stderr)
        return 2
    target = base / "applications/hardcheck.desktop"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Preserve the venv path: resolving the Python symlink would lose the venv.
        executable = desktop_quote(os.path.abspath(sys.executable))
        content = (
            "[Desktop Entry]\nType=Application\nName=HardCheck\n"
            "Comment=Read-only local Linux security audit\n"
            f"Exec={executable} -m hardcheck serve --open-browser\n"
            "Icon=security-high\nTerminal=false\nCategories=System;Security;\n"
            "StartupNotify=false\n" + MARKER + "\n"
        )
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(parent_fd)
            if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                raise ValueError("Unsafe launcher directory")
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                descriptor = os.open(target.name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                descriptor = None if remove else os.open(
                    target.name, flags | os.O_CREAT | os.O_EXCL, 0o644,
                    dir_fd=parent_fd,
                )
                new = True
            else:
                new = False
            if descriptor is not None:
                with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
                    metadata = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1
                        or metadata.st_mode & 0o022
                    ):
                        raise ValueError("Unsafe launcher file")
                    if not new and MARKER not in stream.read(65537).splitlines():
                        raise ValueError("Unmanaged launcher")
                    if remove:
                        os.unlink(target.name, dir_fd=parent_fd)
                    else:
                        stream.seek(0)
                        stream.truncate(0)
                        stream.write(content)
        finally:
            os.close(parent_fd)
        if remove:
            print("HardCheck başlatıcısı kaldırıldı.")
            return 0
        print("HardCheck uygulama menüsüne eklendi. Menüyü yeniden açın.")
        return 0
    except (OSError, ValueError, UnicodeError):
        print(
            "Başlatıcı güncellenemedi; mevcut kullanıcı dosyaları korundu.",
            file=sys.stderr,
        )
        return 2
