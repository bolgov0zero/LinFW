from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .lists import list_ref

CHAINS = ("INPUT", "OUTPUT", "FORWARD")
PROTOCOLS = ("all", "tcp", "udp", "icmp")
ACTIONS = ("ACCEPT", "DROP", "REJECT")

# LinFW owns one nftables table and never touches the others (docker, fail2ban ...).
FAMILY = "ip"
TABLE = "linfw"
SET_TYPE = "type ipv4_addr; flags interval;"

# Every rule carries its role in an nft comment: that is how a rule is recognised again.
#   linfw:rule              an ordinary rule
#   linfw:off:<action>[:log]  a rule switched off: it keeps all its matches but its verdict
#                           is `continue`, so the packet goes on to the next rule; the comment
#                           remembers what the verdict was (and whether logging was on)
#   linfw:log               the hidden twin that logs a packet before the rule below it decides
#   linfw:base:<id>         a base rule (loopback, established/related)
RULE_TAG = "linfw:rule"
OFF_TAG = "linfw:off"
LOG_TAG = "linfw:log"
BASE_TAG = "linfw:base"

# Logging: a rule with "write to the journal" is preceded by a hidden twin with the same
# matches whose statements are `limit` + `log group`. The twin has no verdict, so the packet
# goes on to the real rule. The log statement hands the packet to NFLOG (netlink), where the
# linfw-logd service records it; the limit keeps a busy rule from flooding the journal.
LOG_PREFIX = "LINFW"  # the packet prefix is "LINFW:<CHAIN>:<ACTION>: "
LOG_GROUP = 40  # nflog group shared by the twin rules and linfw-logd
LOG_RATE = "10/minute"
LOG_BURST = "10"

# Base rules: always on top of the chain, never shown in the table and never editable.
BASE_RULES = {
    "INPUT": [("lo", ["iifname", '"lo"', "accept"]), ("est", ["ct", "state", "established,related", "accept"])],
    "OUTPUT": [("lo", ["oifname", '"lo"', "accept"]), ("est", ["ct", "state", "established,related", "accept"])],
    "FORWARD": [("est", ["ct", "state", "established,related", "accept"])],
}


def log_prefix(chain: str, action: str) -> str:
    return f"{LOG_PREFIX}:{chain}:{action.upper()}: "


def log_tokens(chain: str, action: str) -> List[str]:
    """The statements of a log twin, after its matches."""
    return ["limit", "rate", LOG_RATE, "burst", LOG_BURST, "packets", "log", "prefix", f'"{log_prefix(chain, action)}"', "group", str(LOG_GROUP)]


def base_ids(chain: str) -> List[str]:
    return [f"{BASE_TAG}:{name}" for name, _ in BASE_RULES[chain]]


def base_spec(chain: str, tag: str) -> List[str]:
    name = tag[len(BASE_TAG) + 1:]
    return list(next(spec for n, spec in BASE_RULES[chain] if n == name))


class FirewallError(Exception):
    """A user-presentable failure while talking to nftables."""


@dataclass(frozen=True)
class Rule:
    chain: str
    index: int  # 1-based position inside the chain, hidden rules included
    pkts: int
    bytes: int
    protocol: str
    source: str
    destination: str
    port: str
    action: str  # lower-case verdict; for disabled rules, the original action
    enabled: bool
    spec: Tuple[str, ...]  # the rule as nft words, as if it were switched on (counter and comment left out)
    extra: Tuple[str, ...] = ()  # matches that have no column of their own
    number: int = 0  # position shown to the user: hidden rules are not counted
    log: bool = False  # logging is on: a hidden twin sits right above this rule (or, if off, the comment says so)
    tag: str = ""  # the rule's nft comment (see RULE_TAG ...)

    @property
    def key(self) -> str:
        return f"{self.chain}:{self.index}"

    @property
    def base_id(self) -> Optional[str]:
        return self.tag if self.tag.startswith(BASE_TAG + ":") else None

    @property
    def is_log(self) -> bool:
        """True for the hidden log twin of the rule below it."""
        return self.tag == LOG_TAG

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
        """The rule as nft would take it, for copying."""
        words = list(self.spec) if self.enabled else [*self.spec[:-1], "continue"]
        return f"nft add rule {FAMILY} {TABLE} {self.chain.lower()} {' '.join(words)}"


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

    def match_spec(self) -> List[str]:
        """The matches of the rule in nft words (the same words a listing of the rule gives back)."""
        spec: List[str] = []
        port = self.port.replace(":", "-")
        if port:
            spec += [self.protocol, "dport", "{" + port + "}" if "," in port else port]
        elif self.protocol != "all":
            spec += ["ip", "protocol", self.protocol]
        if self.source:
            spec += ["ip", "saddr", self.source]
        if self.destination:
            spec += ["ip", "daddr", self.destination]
        return spec

    def to_spec(self) -> List[str]:
        return self.match_spec() + [self.action.lower()]

    def to_log_spec(self) -> List[str]:
        """The hidden twin: the same matches, then limit + log (no verdict)."""
        return self.match_spec() + log_tokens(self.chain, self.action)


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
