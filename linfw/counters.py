"""Packet/byte counters that survive resets.

iptables keeps its counters in the kernel, and they start from zero after a
reboot (the saved rules carry no counters), after a rule is replaced, or when
another tool reloads the rules. LinFW therefore keeps its own running totals.

A rule is identified by its chain plus its normalized definition (and, for exact
duplicates, an occurrence number), so a total follows a rule when it is moved,
switched off or restored after a reboot. Every sample adds only what the kernel
counter gained since the previous one; a counter that went *down* means it was
reset, so the new value counts in full. A change of boot (see `_epoch`) counts
every rule's new value in full, which also catches resets that climb back above
the old value before the next sample.
"""
from __future__ import annotations

import json
import os
import shlex
import threading
import time
from contextlib import contextmanager
from typing import Callable, Dict, Iterator, List, Optional, Tuple

try:  # not available on every platform; the store then works without cross-process locking
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

from .model import OFF_PREFIX, Rule
from .parser import Snapshot

COUNTERS_FILE = "/var/lib/linfw/counters.json"
FORGET_AFTER = 30 * 24 * 3600  # keep the total of a rule that disappeared for this long
_REFRESH_SEEN = 3600  # how often an unchanged entry's "seen" stamp is rewritten


def signature(spec) -> str:
    """The rule's identity: its definition as if it were switched on, without
    --reject-with (which is lost while a REJECT rule is off)."""
    out: List[str] = []
    i = 0
    spec = list(spec)
    while i < len(spec):
        tok = spec[i]
        if tok == "--reject-with":
            i += 2
        elif tok in ("-j", "--jump") and i + 1 < len(spec) and spec[i + 1].startswith(OFF_PREFIX):
            out += [tok, spec[i + 1][len(OFF_PREFIX):]]
            i += 2
        else:
            out.append(tok)
            i += 1
    return shlex.join(out)


def store_key(chain: str, sig: str, occurrence: int) -> str:
    return f"{chain}|{sig}|{occurrence}"


def assign_keys(snap: Snapshot) -> Dict[str, Tuple[str, Rule]]:
    """{"CHAIN:index": (store key, rule)} for every visible rule."""
    keys: Dict[str, Tuple[str, Rule]] = {}
    for chain, rules in snap.rules.items():
        seen: Dict[str, int] = {}
        for rule in rules:
            if rule.hidden:
                continue
            sig = signature(rule.spec)
            n = seen.get(sig, 0)
            seen[sig] = n + 1
            keys[rule.key] = (store_key(chain, sig, n), rule)
    return keys


def _epoch() -> str:
    """Identifies this boot (and, in a container, this container start)."""
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            boot = fh.read().strip()
    except OSError:
        boot = ""
    try:
        with open("/proc/1/stat") as fh:
            started = fh.read().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        started = ""
    return f"{boot}:{started}"


class CounterStore:
    """JSON file with the running totals; `path=None` keeps them in memory (demo, tests)."""

    def __init__(self, path: Optional[str] = COUNTERS_FILE, epoch: Callable[[], str] = _epoch) -> None:
        self.path = path
        self._epoch = epoch
        self._memory: Dict = {}
        self._thread_lock = threading.RLock()
        self._depth = 0

    # -- storage ---------------------------------------------------------

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Exclusive access across threads and processes (LinFW and linfw-logd).
        Re-entrant, so a caller can hold it around several operations."""
        with self._thread_lock:
            if self._depth == 0 and self.path and fcntl is not None:
                os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
                lock = open(self.path + ".lock", "a")
                fcntl.flock(lock, fcntl.LOCK_EX)
            else:
                lock = None
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if lock:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    lock.close()

    _locked = locked

    def _load(self) -> Dict:
        if not self.path:
            return self._memory
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: Dict) -> None:
        if not self.path:
            self._memory = data
            return
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)

    # -- operations ------------------------------------------------------

    def update(self, snap: Snapshot, now: Optional[float] = None) -> Dict[str, Tuple[int, int]]:
        """Fold the kernel's current counters into the totals; returns
        {"CHAIN:index": (total packets, total bytes)} for the visible rules."""
        now = time.time() if now is None else now
        with self._locked():
            data = self._load()
            rules: Dict[str, Dict] = data.setdefault("rules", {})
            epoch = self._epoch()
            new_boot = data.get("epoch") != epoch
            dirty = new_boot
            data["epoch"] = epoch
            totals: Dict[str, Tuple[int, int]] = {}
            live = set()
            for real_key, (key, rule) in assign_keys(snap).items():
                live.add(key)
                entry = rules.get(key)
                if entry is None:
                    entry = {"p": rule.pkts, "b": rule.bytes}
                    dirty = True
                else:
                    reset = new_boot or rule.pkts < entry["lp"] or rule.bytes < entry["lb"]
                    gained_p = rule.pkts if reset else rule.pkts - entry["lp"]
                    gained_b = rule.bytes if reset else rule.bytes - entry["lb"]
                    if gained_p or gained_b or (rule.pkts, rule.bytes) != (entry["lp"], entry["lb"]):
                        dirty = True
                    entry["p"] += gained_p
                    entry["b"] += gained_b
                entry["lp"], entry["lb"] = rule.pkts, rule.bytes
                if now - entry.get("seen", 0) > _REFRESH_SEEN:
                    entry["seen"] = now
                    dirty = True
                rules[key] = entry
                totals[real_key] = (entry["p"], entry["b"])
            for key in [k for k in rules if k not in live and now - rules[k].get("seen", 0) > FORGET_AFTER]:
                del rules[key]
                dirty = True
            if dirty:
                self._save(data)
            return totals

    def rebase(self, old_key: str, new_key: str) -> Optional[Dict]:
        """A rule is about to be rewritten: its total follows it to the new
        definition, and the kernel counter will restart at zero, so the baseline
        is zero too. Returns the displaced entry for `restore`. Call it (and the
        rewrite) inside `locked()` so no sample falls in between."""
        with self.locked():
            data = self._load()
            rules = data.get("rules", {})
            entry = rules.pop(old_key, None)
            if entry is None:
                return None
            saved = dict(entry)
            entry["lp"] = entry["lb"] = 0
            rules[new_key] = entry
            self._save(data)
            return saved

    def restore(self, old_key: str, new_key: str, entry: Dict) -> None:
        """The rewrite failed: put the total back as it was."""
        with self.locked():
            data = self._load()
            rules = data.get("rules", {})
            if new_key != old_key:
                rules.pop(new_key, None)
            rules[old_key] = entry
            self._save(data)

    def forget(self, key: str) -> None:
        with self._locked():
            data = self._load()
            if data.get("rules", {}).pop(key, None) is not None:
                self._save(data)
