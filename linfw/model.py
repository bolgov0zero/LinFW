from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .lists import list_ref, set_name

CHAINS = ("INPUT", "OUTPUT", "FORWARD")
PROTOCOLS = ("all", "tcp", "udp", "icmp")
ACTIONS = ("ACCEPT", "DROP", "REJECT")

# iptables has no native "disabled" flag. A disabled rule keeps all its matches
# but jumps to an empty user chain, which is a no-op: the packet returns and is
# evaluated against the next rule. One chain per action remembers the original.
OFF_PREFIX = "LINFW_OFF_"
OFF_CHAINS = tuple(OFF_PREFIX + a for a in ACTIONS) + (OFF_PREFIX + "LOG",)

# Logging: a rule with "write to the journal" is preceded by a hidden twin rule
# with the same matches whose target is NFLOG (non-terminating: the packet goes on
# to the real rule). NFLOG hands the packet to userspace over netlink, where the
# linfw-logd service records it; unlike LOG it does not depend on the kernel ring
# buffer, which containers cannot read. The twin is rate-limited so a busy rule
# cannot flood the journal.
LOG_TAG = "linfw:log"
LOG_PREFIX = "LINFW"  # the packet prefix is "LINFW:<CHAIN>:<ACTION>: "
LOG_GROUP = 40  # nflog group shared by the twin rules and linfw-logd
LOG_RATE = "10/min"
LOG_BURST = "10"
LOG_TARGETS = ("LOG", "NFLOG")  # LOG is what earlier versions installed


# Base rules: always on top of the chain, never shown in the table and never
# editable. Every one of them carries a comment "linfw:base:<id>" that is how
# we recognise (and restore) them.
BASE_TAG = "linfw:base"
_ESTABLISHED = ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"]
BASE_RULES = {
    "INPUT": [("lo", ["-i", "lo"]), ("est", _ESTABLISHED)],
    "OUTPUT": [("lo", ["-o", "lo"]), ("est", _ESTABLISHED)],
    "FORWARD": [("est", _ESTABLISHED)],
}


def log_prefix(chain: str, action: str) -> str:
    return f"{LOG_PREFIX}:{chain}:{action}: "


def nflog_target(chain: str, action: str, prefix: Optional[str] = None) -> List[str]:
    return ["-j", "NFLOG", "--nflog-group", str(LOG_GROUP), "--nflog-prefix", prefix or log_prefix(chain, action)]


def base_ids(chain: str) -> List[str]:
    return [f"{BASE_TAG}:{name}" for name, _ in BASE_RULES[chain]]


def base_specs(chain: str) -> List[List[str]]:
    return [
        [*match, "-m", "comment", "--comment", f"{BASE_TAG}:{name}", "-j", "ACCEPT"]
        for name, match in BASE_RULES[chain]
    ]


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
    number: int = 0  # position shown to the user: hidden rules are not counted
    log: bool = False  # a hidden log twin sits right above this rule

    @property
    def key(self) -> str:
        return f"{self.chain}:{self.index}"

    @property
    def base_id(self) -> Optional[str]:
        for i, tok in enumerate(self.spec[:-1]):
            if tok == "--comment" and self.spec[i + 1].startswith(BASE_TAG + ":"):
                return self.spec[i + 1]
        return None

    @property
    def is_log(self) -> bool:
        """True for the hidden LOG twin of the rule below it."""
        return any(
            tok == "--comment" and self.spec[i + 1] == LOG_TAG for i, tok in enumerate(self.spec[:-1])
        )

    @property
    def hidden(self) -> bool:
        return self.base_id is not None or self.is_log

    @property
    def editable(self) -> bool:
        """True if the add/edit dialog can represent this rule without losing conditions."""
        return (
            not self.hidden
            and not self.extra
            and self.protocol in PROTOCOLS
            and self.action.upper() in ACTIONS
            and not any(s.startswith("!") for s in (self.source, self.destination, self.port))
            and not self.port.startswith(("sp:", "dp:"))
        )

    def to_new(self) -> "NewRule":
        return NewRule(
            self.chain, self.protocol, self.action.upper(), self.source, self.destination, self.port, self.log
        )

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
    log: bool = False

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
            bool(self.log),
        )

    def used_lists(self) -> List[str]:
        return [n for n in (list_ref(self.source), list_ref(self.destination)) if n]

    def to_spec(self) -> List[str]:
        spec: List[str] = []
        if self.protocol != "all":
            spec += ["-p", self.protocol]
        for flag, value, direction in (("-s", self.source, "src"), ("-d", self.destination, "dst")):
            name = list_ref(value) if value else None
            if name:
                spec += ["-m", "set", "--match-set", set_name(name), direction]
            elif value:
                spec += [flag, value]
        if self.port:
            if "," in self.port:
                spec += ["-m", "multiport", "--dports", self.port]
            else:
                spec += ["--dport", self.port]
        return spec + ["-j", self.action]

    def to_log_spec(self, enabled: bool = True) -> List[str]:
        """The hidden twin: same matches, then LOG (or, while the rule is switched
        off, a jump to the empty LINFW_OFF_LOG chain)."""
        spec = self.to_spec()[:-2] + ["-m", "comment", "--comment", LOG_TAG]
        spec += ["-m", "limit", "--limit", LOG_RATE, "--limit-burst", LOG_BURST]
        if enabled:
            return spec + nflog_target(self.chain, self.action)
        return spec + ["-j", OFF_PREFIX + "LOG"]


def _normalize_address(value: str, label: str) -> str:
    value = value.strip()
    if value.lower() in ("", "any", "anywhere", "*"):
        return ""
    if value.startswith("@"):
        if not list_ref(value):
            raise ValueError(f"{label}: неверное имя списка (латиница, цифры, «_», «-», «.»)")
        return value  # the list itself is checked against the existing ones when the rule is applied
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
