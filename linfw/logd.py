"""linfw-logd: records the packets that rules with logging on send to NFLOG.

Run by systemd (`linfw --logd`). Appends one line per packet to HITS_FILE and
rotates it at MAX_BYTES, keeping a single previous generation.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Optional

from . import nflog
from .journal import HITS_FILE, LogEntry, format_hit
from .model import LOG_GROUP, LOG_PREFIX

MAX_BYTES = 5 * 1024 * 1024


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
    def __init__(self, path: str = HITS_FILE, max_bytes: int = MAX_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        self._fh = open(path, "a", buffering=1)

    def write(self, entry: LogEntry) -> None:
        if self._fh.tell() >= self.max_bytes:
            self._fh.close()
            os.replace(self.path, self.path + ".1")
            self._fh = open(self.path, "a", buffering=1)
        self._fh.write(format_hit(entry) + "\n")

    def close(self) -> None:
        self._fh.close()


def run(path: str = HITS_FILE, group: int = LOG_GROUP) -> None:
    writer = HitWriter(path)
    try:
        with nflog.Listener(group) as listener:
            print(f"linfw-logd: listening on nflog group {group}, writing to {path}", flush=True)
            for packet in listener.packets():
                entry = entry_from_packet(packet)
                if entry:
                    writer.write(entry)
    except OSError as exc:
        sys.exit(f"linfw-logd: {exc}")
    finally:
        writer.close()
