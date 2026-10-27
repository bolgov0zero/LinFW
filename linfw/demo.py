"""In-memory stand-in for iptables, used by `linfw --demo` and the tests.

It understands just the subset of the command line that Firewall emits and
renders `iptables-save -c` text, so the real parser runs against it.
"""
from __future__ import annotations

import random
import shlex
from typing import Dict, List, Optional, Tuple

from .model import CHAINS, FirewallError

_SAMPLE = [
    ("INPUT", "-p tcp --dport 22 -j ACCEPT", 1532),
    ("INPUT", "-p tcp -m multiport --dports 80,443 -j ACCEPT", 20871),
    ("INPUT", "-p icmp -j ACCEPT", 87),
    ("INPUT", "-s 203.0.113.0/24 -j DROP", 311),
    ("INPUT", "-p udp --dport 161 -s 10.0.0.0/8 -j REJECT --reject-with icmp-port-unreachable", 12),
    ("INPUT", "-j DROP", 5400),
    ("OUTPUT", "-p tcp -d 198.51.100.7 --dport 25 -j DROP", 3),
    ("OUTPUT", "-j ACCEPT", 120442),
    ("FORWARD", "-s 192.168.1.0/24 -d 10.10.0.0/16 -j ACCEPT", 9120),
    ("FORWARD", "-j REJECT --reject-with icmp-port-unreachable", 15),
]


class DemoRunner:
    def __init__(self, sample: bool = True, jitter: bool = True) -> None:
        self.policies = {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"}
        self.user_chains: List[str] = []
        self.rules: Dict[str, List[List]] = {c: [] for c in CHAINS}  # [pkts, bytes, tokens]
        self.persist_calls = 0
        self._jitter = jitter
        if sample:
            for chain, line, pkts in _SAMPLE:
                self.rules[chain].append([pkts, pkts * 90, shlex.split(line)])

    def _chain(self, name: str) -> List[List]:
        if name not in self.rules:
            raise FirewallError(f"iptables: No chain/target/match by that name: {name}")
        return self.rules[name]

    @staticmethod
    def _split_counters(args: List[str]) -> Tuple[List[str], int, int]:
        if "-c" in args:
            i = args.index("-c")
            return args[:i] + args[i + 3:], int(args[i + 1]), int(args[i + 2])
        return args, 0, 0

    def ipt(self, args: List[str]) -> None:
        op, rest = args[0], args[1:]
        if op == "-N":
            if rest[0] in self.user_chains:
                raise FirewallError("iptables: Chain already exists.")
            self.user_chains.append(rest[0])
            return
        chain = self._chain(rest[0])
        if op == "-D":
            self._index(chain, int(rest[1]))
            del chain[int(rest[1]) - 1]
        elif op == "-A":
            tokens, pkts, nbytes = self._split_counters(rest[1:])
            chain.append([pkts, nbytes, tokens])
        elif op == "-I":
            tokens, pkts, nbytes = self._split_counters(rest[2:])
            if not 1 <= int(rest[1]) <= len(chain) + 1:
                raise FirewallError("iptables: Index of insertion too big.")
            chain.insert(int(rest[1]) - 1, [pkts, nbytes, tokens])
        elif op == "-R":
            self._index(chain, int(rest[1]))
            tokens, pkts, nbytes = self._split_counters(rest[2:])
            chain[int(rest[1]) - 1] = [pkts, nbytes, tokens]
        else:
            raise FirewallError(f"demo: unsupported operation {op}")

    @staticmethod
    def _index(chain: List[List], n: int) -> None:
        if not 1 <= n <= len(chain):
            raise FirewallError("iptables: Index of deletion too big.")

    def save_text(self) -> str:
        if self._jitter:
            for chain in self.rules.values():
                for entry in chain:
                    if random.random() < 0.2:
                        entry[0] += random.randint(1, 40)
                        entry[1] += random.randint(60, 4000)
        lines = ["*filter"]
        lines += [f":{c} {self.policies[c]} [0:0]" for c in CHAINS]
        lines += [f":{c} - [0:0]" for c in self.user_chains]
        for name, chain in self.rules.items():
            for pkts, nbytes, tokens in chain:
                lines.append(f"[{pkts}:{nbytes}] -A {name} {shlex.join(tokens)}")
        lines.append("COMMIT")
        return "\n".join(lines) + "\n"

    def persist(self) -> str:
        self.persist_calls += 1
        return "demo (не сохраняется)"

    def persist_info(self) -> Optional[str]:
        return "demo"
