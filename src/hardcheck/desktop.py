"""Install a per-user Linux application entry without privileged services."""

import os
import platform
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
        if target.is_symlink() or (
            target.exists() and MARKER not in target.read_text()
        ):
            raise ValueError("Unmanaged launcher")
        if remove:
            target.unlink(missing_ok=True)
            print("HardCheck başlatıcısı kaldırıldı.")
            return 0
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
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "w") as stream:
            stream.truncate(0)
            stream.write(content)
        print("HardCheck uygulama menüsüne eklendi. Menüyü yeniden açın.")
        return 0
    except (OSError, ValueError):
        print(
            "Başlatıcı güncellenemedi; mevcut kullanıcı dosyaları korundu.",
            file=sys.stderr,
        )
        return 2
