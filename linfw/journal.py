"""Reading rule hits back from the kernel log.

A rule with logging on is preceded by a hidden iptables LOG rule whose prefix is
"LINFW:<CHAIN>:<ACTION>: ". The kernel writes such packets to its log as e.g.
    LINFW:INPUT:DROP: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=5555 DPT=22 ...
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from . import persist
from .model import LOG_PREFIX, FirewallError

MAX_ENTRIES = 1000

_HIT = re.compile(rf"{LOG_PREFIX}:(?P<chain>[A-Z]+):(?P<action>[A-Z]+):\s*(?P<rest>.*)")
_FIELD = re.compile(r"(\w+)=(\S*)")
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
_SYSLOG = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_DMESG_T = re.compile(r"^\[\w{3} (\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\d{4})\]")

_LOG_FILES = ("/var/log/kern.log", "/var/log/messages", "/var/log/syslog")


@dataclass(frozen=True)
class LogEntry:
    time: str
    chain: str
    action: str  # lower-case
    protocol: str
    source: str
    destination: str
    port: str


def _timestamp(line: str) -> str:
    m = _ISO.match(line)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = _DMESG_T.match(line)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = _SYSLOG.match(line)
    return m.group(1) if m else ""


def parse_line(line: str) -> Optional[LogEntry]:
    hit = _HIT.search(line)
    if not hit:
        return None
    fields = dict(_FIELD.findall(hit.group("rest")))
    if "SRC" not in fields or "DST" not in fields:
        return None
    protocol = fields.get("PROTO", "").lower() or "?"
    port = fields.get("DPT", "") if protocol in ("tcp", "udp") else ""
    return LogEntry(
        time=_timestamp(line),
        chain=hit.group("chain"),
        action=hit.group("action").lower(),
        protocol=protocol,
        source=fields["SRC"],
        destination=fields["DST"],
        port=port or "-",
    )


def parse_text(text: str) -> List[LogEntry]:
    entries = [e for e in map(parse_line, (ln for ln in text.splitlines() if LOG_PREFIX + ":" in ln)) if e]
    return entries[-MAX_ENTRIES:]


def _run(argv: List[str]) -> Optional[str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def _tail(path: str, nbytes: int = 4_000_000) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - nbytes))
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return None


def read_entries() -> Tuple[str, List[LogEntry]]:
    """Return (source name, entries oldest-first) from the first readable source:
    journald, a classic log file, then dmesg."""
    journalctl = persist.find_binary("journalctl")
    if journalctl:
        text = _run([journalctl, "-k", "-o", "short-iso", "--no-pager", "-q", "-n", "20000"])
        if text is not None:
            return "journalctl -k", parse_text(text)
    for path in _LOG_FILES:
        text = _tail(path)
        if text is not None:
            return path, parse_text(text)
    dmesg = persist.find_binary("dmesg")
    if dmesg:
        text = _run([dmesg, "-T"])
        if text is not None:
            return "dmesg", parse_text(text)
    raise FirewallError("Журнал ядра недоступен: не удалось прочитать journalctl, kern.log, messages, syslog и dmesg")
