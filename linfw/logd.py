"""linfw-logd, the background service (`linfw --logd`, run by systemd).

It does two jobs that must not depend on the UI being open:
  * records the packets that rules with logging on send to NFLOG, one file per
    day, deleting files older than RETENTION_DAYS;
  * samples the iptables counters every SAMPLE_SECONDS into the running totals
    (see counters.py), and once more on shutdown, so no hits are lost to resets.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
from datetime import date, datetime, timedelta
from typing import Optional

from . import nflog
from .counters import COUNTERS_FILE, CounterStore
from .firewall import Firewall, SystemRunner
from .journal import HITS_DIR, RETENTION_DAYS, LogEntry, day_file, format_hit, list_hit_files
from .model import LOG_GROUP, LOG_PREFIX, FirewallError

SAMPLE_SECONDS = 5
PRUNE_SECONDS = 3600


def entry_from_packet(packet: nflog.Packet, now: Optional[datetime] = None) -> Optional[LogEntry]:
    """Turn an nflog packet into a journal record; None if it is not one of ours."""
    parts = packet.prefix.strip().split(":")
    if len(parts) < 3 or parts[0] != LOG_PREFIX:
        return None
    hit = nflog.parse_ipv4(packet.payload)
    if not hit:
        return None
    stamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    return LogEntry(stamp, parts[1], parts[2].lower(), hit.protocol, hit.source, hit.destination, hit.port)


class HitWriter:
    """Appends records to the file of their day and keeps `keep_days` days of files."""

    def __init__(self, directory: str = HITS_DIR, keep_days: int = RETENTION_DAYS) -> None:
        self.directory = directory
        self.keep_days = keep_days
        self._day: Optional[str] = None
        self._fh = None
        self._lock = threading.Lock()
        os.makedirs(directory, mode=0o750, exist_ok=True)
        self.prune()

    def write(self, entry: LogEntry) -> None:
        day = entry.time[:10]
        with self._lock:
            if day != self._day:
                if self._fh:
                    self._fh.close()
                self._fh = open(day_file(self.directory, date.fromisoformat(day)), "a", buffering=1)
                self._day = day
            self._fh.write(format_hit(entry) + "\n")

    def prune(self, today: Optional[date] = None) -> None:
        """Delete files of days older than the retention period (and stale files of the first version)."""
        cutoff = (today or date.today()) - timedelta(days=self.keep_days)
        for path in list_hit_files(self.directory):
            name = os.path.basename(path)
            try:
                if name.startswith("hits-"):
                    old = date.fromisoformat(name[5:15]) < cutoff
                else:
                    old = datetime.fromtimestamp(os.path.getmtime(path)).date() < cutoff
                if old:
                    os.remove(path)
            except (OSError, ValueError):
                continue

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


def _sample(fw: Firewall) -> None:
    try:
        fw.counter_totals(fw.snapshot())
    except FirewallError as exc:
        print(f"linfw-logd: не удалось прочитать счётчики: {exc}", file=sys.stderr, flush=True)


def _sampler(fw: Firewall, writer: HitWriter, stop: threading.Event) -> None:
    pruned = 0.0
    while not stop.wait(SAMPLE_SECONDS):
        _sample(fw)
        pruned += SAMPLE_SECONDS
        if pruned >= PRUNE_SECONDS:
            writer.prune()
            pruned = 0.0


def _terminate(*_args) -> None:
    raise SystemExit(0)


def run(directory: str = HITS_DIR, group: int = LOG_GROUP, counters_path: str = COUNTERS_FILE) -> None:
    try:
        fw = Firewall(SystemRunner(), CounterStore(counters_path))
    except FirewallError as exc:
        sys.exit(f"linfw-logd: {exc}")
    writer = HitWriter(directory)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, _terminate)
    thread = threading.Thread(target=_sampler, args=(fw, writer, stop), daemon=True)
    thread.start()
    _sample(fw)
    try:
        try:
            with nflog.Listener(group) as listener:
                print(f"linfw-logd: nflog group {group} -> {directory}; counters every {SAMPLE_SECONDS}s", flush=True)
                for packet in listener.packets():
                    entry = entry_from_packet(packet)
                    if entry:
                        writer.write(entry)
        except OSError as exc:
            # the journal cannot work here, but the counters still must be kept
            print(f"linfw-logd: журнал срабатываний недоступен: {exc}", file=sys.stderr, flush=True)
            stop.wait()
    finally:
        stop.set()
        _sample(fw)  # last sample before the rules go away
        writer.close()
