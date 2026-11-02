"""Make the rules survive a reboot.

LinFW keeps its table in one file, /etc/linfw/linfw.nft, that `nft -f` loads in one step
(it replaces the whole table, sets included, so rules never come up without their lists).
The systemd unit linfw.service, written by install.sh, loads it early in the boot.
"""
from __future__ import annotations

import os
import shutil
from typing import Optional

from .model import FirewallError

_SBIN = ("/usr/sbin", "/sbin", "/usr/local/sbin")
RULES_FILE = "/etc/linfw/linfw.nft"
UNIT_FILE = "/etc/systemd/system/linfw.service"


def find_binary(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for d in _SBIN:
        path = os.path.join(d, name)
        if os.access(path, os.X_OK):
            return path
    return None


def describe() -> Optional[str]:
    """Name of the persistence mechanism, or None if nothing is configured."""
    return "linfw.nft" if os.path.exists(UNIT_FILE) else None


def save(text: str, path: str = RULES_FILE) -> str:
    """Write the table file (atomically); returns a short status message."""
    if not describe():
        raise FirewallError(
            "Автосохранение не настроено: после перезагрузки правила пропадут. "
            "Запустите install.sh ещё раз."
        )
    tmp = path + ".linfw-tmp"
    try:
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        raise FirewallError(f"Не удалось сохранить правила: {exc}") from None
    return describe() or ""
