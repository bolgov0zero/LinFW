"""In-memory stand-in for nftables, used by `linfw --demo` and the tests.

It understands just the subset of nft commands that Firewall emits and prints the table
in the format of `nft list table ip linfw`, so the real parser runs against it.
"""
from __future__ import annotations

import copy
import ipaddress
import random
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .journal import LogEntry
from .model import CHAINS, FAMILY, RULE_TAG, TABLE, FirewallError
from .parser import words
from .render import rule_words

_SAMPLE = [
    ("INPUT", "tcp dport 22 accept", 1532),
    ("INPUT", "tcp dport {80,443} accept", 20871),
    ("INPUT", "ip protocol icmp accept", 87),
    ("INPUT", "ip saddr @blocklist drop", 311),
    ("INPUT", "udp dport 161 ip saddr 10.0.0.0/8 reject", 12),
    ("INPUT", "drop", 5400),
    ("OUTPUT", "tcp dport 25 ip daddr 198.51.100.7 drop", 3),
    ("OUTPUT", "accept", 120442),
    ("FORWARD", "ip saddr 192.168.1.0/24 ip daddr 10.10.0.0/16 accept", 9120),
    ("FORWARD", "reject", 15),
]

_CHAIN = re.compile(r"^add chain \S+ \S+ (\w+) \{.*policy (\w+);")
_HOOKS = {"INPUT": "input", "OUTPUT": "output", "FORWARD": "forward"}


_DEMO_HITS = [
    ("INPUT", "drop", "tcp", "203.0.113.%d", "192.168.1.10", "22"),
    ("INPUT", "drop", "tcp", "198.51.100.%d", "192.168.1.10", "3389"),
    ("INPUT", "accept", "tcp", "10.0.0.%d", "192.168.1.10", "443"),
    ("INPUT", "reject", "udp", "10.0.0.%d", "192.168.1.10", "161"),
    ("INPUT", "drop", "icmp", "203.0.113.%d", "192.168.1.10", "-"),
    ("OUTPUT", "drop", "tcp", "192.168.1.10", "198.51.100.%d", "25"),
    ("OUTPUT", "accept", "udp", "192.168.1.10", "8.8.8.%d", "53"),
    ("FORWARD", "reject", "tcp", "192.168.1.%d", "10.10.0.5", "8080"),
]


class DemoRunner:
    def __init__(self, sample: bool = True, jitter: bool = True) -> None:
        self.exists = False
        self.policies: Dict[str, str] = {}
        self.rules: Dict[str, List[List]] = {}  # chain -> [[pkts, bytes, words, tag]]
        self.persist_calls = 0
        self.persisted = ""
        self._jitter = jitter
        # address lists: set name -> entries (the real thing lives in the kernel)
        self.sets: Dict[str, List[str]] = {}
        self._hits: List[LogEntry] = []
        if sample:
            self.exists = True
            self.policies = {"INPUT": "accept", "FORWARD": "drop", "OUTPUT": "accept"}
            self.rules = {c: [] for c in CHAINS}
            self.sets = {"office": ["192.168.1.0/24", "10.0.0.5"], "blocklist": ["198.51.100.7", "203.0.113.0/24"]}
            for chain, line, pkts in _SAMPLE:
                self.rules[chain].append([pkts, pkts * 90, words(line), RULE_TAG])
            for _ in range(24):
                self._add_hit(datetime.now() - timedelta(seconds=random.randint(5, 3600)))
            self._hits.sort(key=lambda e: e.time)

    def add_rule(self, chain: str, line: str, pkts: int = 0, nbytes: int = 0, tag: str = RULE_TAG) -> None:
        """Put a rule straight into the table (tests): `tcp dport 22 accept`. The table and the chain are made if needed."""
        self.exists = True
        self.rules.setdefault(chain, [])
        self.policies.setdefault(chain, "accept")
        self.rules[chain].append([pkts, nbytes, words(line), tag])

    # -- what `nft list table` prints ------------------------------------

    def list_table(self) -> Optional[str]:
        if not self.exists:
            return None
        if self._jitter:
            for chain in self.rules.values():
                for entry in chain:
                    if random.random() < 0.2:
                        entry[0] += random.randint(1, 40)
                        entry[1] += random.randint(60, 4000)
        out = [f"table {FAMILY} {TABLE} {{"]
        for name, entries in self.sets.items():
            out += [f"\tset {name} {{", "\t\ttype ipv4_addr", "\t\tflags interval"]
            if entries:
                out.append(f"\t\telements = {{ {', '.join(entries)} }}")
            out += ["\t}", ""]
        for chain, rules in self.rules.items():
            out += [f"\tchain {chain.lower()} {{", f"\t\ttype filter hook {_HOOKS[chain]} priority filter; policy {self.policies.get(chain, 'accept')};"]
            out += [f"\t\t{rule_words(spec, tag, (pkts, nbytes), off=False)}" for pkts, nbytes, spec, tag in rules]
            out += ["\t}", ""]
        out[-1:] = ["}"]
        return "\n".join(out) + "\n"

    # -- what `nft -f -` does ---------------------------------------------

    def nft(self, lines: List[str]) -> None:
        saved = copy.deepcopy((self.exists, self.policies, self.rules, self.sets))
        try:
            for line in lines:
                self._command(line.strip())
        except FirewallError:
            self.exists, self.policies, self.rules, self.sets = saved  # a transaction: all or nothing
            raise

    def _chain(self, name: str) -> List[List]:
        if name.upper() not in self.rules:
            raise FirewallError("No such file or directory")
        return self.rules[name.upper()]

    def _set(self, name: str) -> List[str]:
        if name not in self.sets:
            raise FirewallError("No such file or directory")
        return self.sets[name]

    def _uses(self, name: str) -> bool:
        return any(f"@{name}" in spec for rules in self.rules.values() for _, _, spec, _ in rules)

    def _command(self, line: str) -> None:
        m = _CHAIN.match(line)
        if m:
            self.rules.setdefault(m.group(1).upper(), [])
            self.policies.setdefault(m.group(1).upper(), m.group(2))
            return
        w = words(line)
        if w[:3] == ["table", FAMILY, TABLE]:
            self.exists = True
        elif w[:4] == ["delete", "table", FAMILY, TABLE]:
            self.exists, self.rules, self.policies, self.sets = False, {}, {}, {}
        elif w[:2] == ["flush", "chain"]:
            self._chain(w[4])[:] = []
        elif w[:2] == ["add", "rule"]:
            self._add_rule(w[4], w[5:])
        elif w[:2] == ["add", "set"]:
            if w[4] in self.sets:
                raise FirewallError("File exists")
            self.sets[w[4]] = []
        elif w[:2] == ["delete", "set"]:
            self._set(w[4])
            if self._uses(w[4]):
                raise FirewallError("Could not process rule: Device or resource busy")
            del self.sets[w[4]]
        elif w[:2] == ["add", "element"]:
            entries = self._set(w[4])
            for item in w[5][1:-1].split(","):
                if item in entries:
                    continue
                net = ipaddress.IPv4Network(item, strict=False)
                if any(net.overlaps(ipaddress.IPv4Network(e, strict=False)) for e in entries):
                    raise FirewallError("interval overlaps with an existing one")
                entries.append(item)
        elif w[:2] == ["delete", "element"]:
            entries = self._set(w[4])
            for item in w[5][1:-1].split(","):
                if item not in entries:
                    raise FirewallError("element does not exist")
                entries.remove(item)
        else:
            raise FirewallError(f"demo: unsupported command {line}")

    def _add_rule(self, chain: str, rest: List[str]) -> None:
        rules = self._chain(chain)
        pkts = nbytes = 0
        tag = ""
        if "comment" in rest:
            i = rest.index("comment")
            tag = rest[i + 1].strip('"')
            del rest[i:i + 2]
        if "counter" in rest:
            i = rest.index("counter")
            if rest[i + 1:i + 2] == ["packets"]:
                pkts, nbytes = int(rest[i + 2]), int(rest[i + 4])
                del rest[i:i + 5]
            else:
                del rest[i]
        for word in rest:
            if word.startswith("@") and word[1:] not in self.sets:
                raise FirewallError("No such file or directory")
        rules.append([pkts, nbytes, rest, tag])

    def _add_hit(self, when: datetime) -> None:
        chain, action, proto, src, dst, port = random.choice(_DEMO_HITS)
        fill = lambda s: s % random.randint(2, 250) if "%d" in s else s  # noqa: E731
        self._hits.append(
            LogEntry(when.strftime("%Y-%m-%d %H:%M:%S"), chain, action, proto, fill(src), fill(dst), port)
        )

    def read_journal(self, chain: Optional[str] = None, actions=None, limit: int = 5000) -> Tuple[str, List[LogEntry]]:
        if self._jitter and self._hits:
            for _ in range(random.choice((0, 0, 1, 2))):
                self._add_hit(datetime.now())
        hits = [e for e in self._hits if chain in (None, e.chain) and (not actions or e.action in actions)]
        return "demo", hits[-limit:]

    def logd_state(self) -> Optional[str]:
        return "active"

    def persist(self, text: str) -> str:
        self.persist_calls += 1
        self.persisted = text
        return "demo (не сохраняется)"

    def persist_info(self) -> Optional[str]:
        return "demo"

    def problem(self) -> Optional[str]:
        return None
