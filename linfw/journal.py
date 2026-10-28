"""The journal of rule hits.

A rule with logging on is preceded by a hidden iptables rule that sends matching
packets to NFLOG with the prefix "LINFW:<CHAIN>:<ACTION>: ". The linfw-logd
service records them in one file per day (HITS_DIR/hits-YYYY-MM-DD.log, one
tab-separated record per line) and deletes files older than RETENTION_DAYS.

Records of rules made by earlier versions (target LOG, kernel log) are still
read from journalctl / kern.log / dmesg when there is nothing in HITS_DIR.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import date
from typing import Callable, FrozenSet, List, Optional, Tuple

from . import persist
from .model import LOG_PREFIX, FirewallError

MAX_ENTRIES = 5000  # newest records shown at once
RETENTION_DAYS = 30
HITS_DIR = "/var/log/linfw"
_DAY_FILE = re.compile(r"hits-(\d{4}-\d{2}-\d{2})\.log")
_LEGACY_FILES = ("hits.log.1", "hits.log")  # the single rotating file of the first version

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


# -- our own files -----------------------------------------------------------


def format_hit(e: LogEntry) -> str:
    return "\t".join((e.time, e.chain, e.action, e.protocol, e.source, e.destination, e.port))


def parse_hits(text: str) -> List[LogEntry]:
    entries = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 7:
            entries.append(LogEntry(*parts))
    return entries


def day_file(directory: str, day: date) -> str:
    return os.path.join(directory, f"hits-{day.isoformat()}.log")


def list_hit_files(directory: str) -> List[str]:
    """Record files, oldest first."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    legacy = [n for n in _LEGACY_FILES if n in names]
    dated = sorted(n for n in names if _DAY_FILE.fullmatch(n))
    return [os.path.join(directory, n) for n in legacy + dated]


def _wanted(entry: LogEntry, chain: Optional[str], actions: Optional[FrozenSet[str]]) -> bool:
    """The chain and action filters are independent: an entry must pass both."""
    return chain in (None, entry.chain) and (not actions or entry.action in actions)


def read_hits(
    directory: str = HITS_DIR,
    chain: Optional[str] = None,
    limit: int = MAX_ENTRIES,
    actions: Optional[FrozenSet[str]] = None,
) -> Optional[List[LogEntry]]:
    """The newest `limit` records (oldest first), or None if there is no record directory.
    Files are read newest to oldest and only as far as needed, from their ends."""
    files = list_hit_files(directory)
    if not os.path.isdir(directory):
        return None
    collected: List[LogEntry] = []
    for path in reversed(files):
        text = _tail(path, whole_lines=True)
        if text is None:
            continue
        entries = [e for e in parse_hits(text) if _wanted(e, chain, actions)]
        collected = entries + collected
        if len(collected) >= limit:
            break
    return collected[-limit:]


# -- the kernel log (records of the old LOG target) --------------------------


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


def _tail(path: str, nbytes: int = 2_000_000, whole_lines: bool = False) -> Optional[str]:
    """The last `nbytes` of a file as text; with whole_lines a cut first line is dropped."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            start = max(0, fh.tell() - nbytes)
            fh.seek(start)
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    if whole_lines and start > 0:
        data = data.split("\n", 1)[-1]
    return data


def _from_kernel_log(
    read: Callable[[], Optional[str]], chain: Optional[str], actions: Optional[FrozenSet[str]]
) -> Callable[[], Optional[List[LogEntry]]]:
    def reader() -> Optional[List[LogEntry]]:
        text = read()
        if text is None:
            return None
        return [e for e in parse_text(text) if _wanted(e, chain, actions)]

    return reader


def _sources(chain: Optional[str], actions: Optional[FrozenSet[str]]):
    """Candidate (name, reader) pairs, most likely first. A reader returns entries or None."""
    yield "linfw-logd", lambda: read_hits(HITS_DIR, chain, actions=actions)
    journalctl = persist.find_binary("journalctl")
    if journalctl:
        yield "journalctl -k", _from_kernel_log(
            lambda: _run([journalctl, "-k", "-o", "short-iso", "--no-pager", "-q", "-n", "20000"]), chain, actions
        )
    for path in _LOG_FILES:
        yield path, _from_kernel_log(lambda p=path: _tail(p, 4_000_000), chain, actions)
    dmesg = persist.find_binary("dmesg")
    if dmesg:
        yield "dmesg", _from_kernel_log(lambda: _run([dmesg, "-T"]), chain, actions)


def read_entries(chain: Optional[str] = None, actions: Optional[FrozenSet[str]] = None) -> Tuple[str, List[LogEntry]]:
    """Return (source name, entries oldest-first), optionally only one chain and/or
    only some actions ("accept", "drop", "reject"; the two filters are independent).
    Sources are tried in turn and the first one that has records wins."""
    first_readable = ""
    for name, read in _sources(chain, actions):
        entries = read()
        if entries is None:
            continue
        if entries or (name == "linfw-logd" and list_hit_files(HITS_DIR)):
            # once the service has written files, an empty answer means "nothing matches
            # the filters", not "look elsewhere": the kernel log is only for old LOG rules
            return name, entries
        first_readable = first_readable or name
    if first_readable:
        return first_readable, []
    raise FirewallError("Журнал недоступен: нет файлов службы linfw-logd и не читается журнал ядра")
