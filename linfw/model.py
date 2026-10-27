from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass
from typing import List, Tuple

CHAINS = ("INPUT", "OUTPUT", "FORWARD")
PROTOCOLS = ("all", "tcp", "udp", "icmp")
ACTIONS = ("ACCEPT", "DROP", "REJECT")

# iptables has no native "disabled" flag. A disabled rule keeps all its matches
# but jumps to an empty user chain, which is a no-op: the packet returns and is
# evaluated against the next rule. One chain per action remembers the original.
OFF_PREFIX = "LINFW_OFF_"
OFF_CHAINS = tuple(OFF_PREFIX + a for a in ACTIONS)


class FirewallError(Exception):
    """A user-presentable failure while talking to iptables."""


@dataclass(frozen=True)
class Rule:
    chain: str
    index: int  # 1-based position inside the chain, as iptables counts it
    pkts: int
    bytes: int
    protocol: str
    source: str
    destination: str
    port: str
    action: str  # lower-case target; for disabled rules, the original action
    enabled: bool
    spec: Tuple[str, ...]  # tokens after "-A CHAIN", used to re-issue the rule
    extra: Tuple[str, ...] = ()  # matches that have no column of their own

    @property
    def key(self) -> str:
        return f"{self.chain}:{self.index}"

    def describe(self) -> str:
        return shlex.join(["-A", self.chain, *self.spec])


@dataclass
class NewRule:
    chain: str = "INPUT"
    protocol: str = "all"
    action: str = "ACCEPT"
    source: str = ""
    destination: str = ""
    port: str = ""

    def validated(self) -> "NewRule":
        """Return a normalized copy, or raise ValueError with a Russian message."""
        if self.chain not in CHAINS:
            raise ValueError("Неизвестная цепочка")
        if self.protocol not in PROTOCOLS:
            raise ValueError("Неизвестный протокол")
        if self.action not in ACTIONS:
            raise ValueError("Неизвестное действие")
        port = _normalize_port(self.port)
        if port and self.protocol not in ("tcp", "udp"):
            raise ValueError("Порт можно указать только для tcp или udp")
        return NewRule(
            self.chain,
            self.protocol,
            self.action,
            _normalize_address(self.source, "Source"),
            _normalize_address(self.destination, "Destination"),
            port,
        )

    def to_spec(self) -> List[str]:
        spec: List[str] = []
        if self.protocol != "all":
            spec += ["-p", self.protocol]
        if self.source:
            spec += ["-s", self.source]
        if self.destination:
            spec += ["-d", self.destination]
        if self.port:
            if "," in self.port:
                spec += ["-m", "multiport", "--dports", self.port]
            else:
                spec += ["--dport", self.port]
        return spec + ["-j", self.action]


def _normalize_address(value: str, label: str) -> str:
    value = value.strip()
    if value.lower() in ("", "any", "anywhere", "*"):
        return ""
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        raise ValueError(f"{label}: нужен IPv4-адрес или сеть (например 10.0.0.0/8)") from None
    if net.prefixlen == 0:
        return ""
    return value


def _normalize_port(value: str) -> str:
    value = value.strip().replace(" ", "").replace("-", ":")
    if value.lower() in ("", "any"):
        return ""
    items = value.split(",")
    slots = 0
    for item in items:
        lo, sep, hi = item.partition(":")
        if not (lo.isdigit() and (not sep or hi.isdigit())):
            raise ValueError("Port: например 22, 80,443 или 1000:2000")
        numbers = [int(lo)] + ([int(hi)] if sep else [])
        if any(not 1 <= n <= 65535 for n in numbers):
            raise ValueError("Port: допустимы значения 1–65535")
        if sep and numbers[0] > numbers[1]:
            raise ValueError("Port: начало диапазона больше конца")
        slots += len(numbers)
    # the multiport match holds at most 15 ports, a range takes two slots
    if len(items) > 1 and slots > 15:
        raise ValueError("Port: не больше 15 портов в списке")
    return value
