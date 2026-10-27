"""Make iptables rules survive a reboot.

Every distro restores them differently, so we detect what is installed:
  * Debian/Ubuntu  - netfilter-persistent (package iptables-persistent)
  * RHEL/Fedora    - /etc/sysconfig/iptables (package iptables-services)
  * Arch           - /etc/iptables/iptables.rules (iptables.service)
  * Alpine         - /etc/init.d/iptables save
install.sh installs and enables the matching package.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable, Optional, Tuple

from .model import FirewallError

_SBIN = ("/usr/sbin", "/sbin", "/usr/local/sbin")


def find_binary(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for d in _SBIN:
        path = os.path.join(d, name)
        if os.access(path, os.X_OK):
            return path
    return None


def _write_dump(path: str, dump: str) -> None:
    tmp = path + ".linfw-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(dump)
    os.replace(tmp, path)


def _method() -> Optional[Tuple[str, Callable[[str], None]]]:
    nfp = find_binary("netfilter-persistent")
    if nfp:
        def save_nfp(_dump: str) -> None:
            r = subprocess.run([nfp, "save"], capture_output=True, text=True, timeout=30)
            if r.returncode:
                raise FirewallError((r.stderr or r.stdout).strip() or "netfilter-persistent save failed")
        return "netfilter-persistent", save_nfp

    rhel_service = os.path.exists("/usr/lib/systemd/system/iptables.service")
    for path in ("/etc/sysconfig/iptables", "/etc/iptables/iptables.rules", "/etc/iptables/rules-save"):
        if os.path.exists(path) or (path == "/etc/sysconfig/iptables" and rhel_service):
            return path, lambda dump, p=path: _write_dump(p, dump)
    return None


def describe() -> Optional[str]:
    """Name of the persistence mechanism, or None if nothing is configured."""
    m = _method()
    return m[0] if m else None


def save(dump: str) -> str:
    """Persist the full `iptables-save` dump; returns a short status message."""
    m = _method()
    if not m:
        raise FirewallError(
            "Автосохранение не настроено: после перезагрузки правила пропадут. "
            "Запустите install.sh ещё раз."
        )
    label, writer = m
    try:
        writer(dump)
    except OSError as exc:
        raise FirewallError(f"Не удалось сохранить правила: {exc}") from None
    return label
