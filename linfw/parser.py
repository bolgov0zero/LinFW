"""Read `nft list table ip linfw` into rules.

A rule line looks like
    tcp dport 22 counter packets 1532 bytes 138000 accept comment "linfw:rule"
It is cut into words; the counter and the comment are taken out, the rest (the
matches and the verdict) is the rule's `spec`. The words are made canonical on the way
(`ip protocol 6` -> `ip protocol tcp`, `ssh` -> `22`), so the same rule always has the
same spec and a spec can be compared with what NewRule.to_spec() produces.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Set, Tuple

from .model import (
    BASE_TAG,
    CHAINS,
    LOG_TAG,
    OFF_TAG,
    RULE_TAG,
    Rule,
)

_WORDS = re.compile(r'"[^"]*"|\{[^}]*\}|\S+')
_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp"}
VERDICTS = ("accept", "drop", "reject", "continue", "return")
_POLICY = re.compile(r"policy\s+(\w+)")
_CHAIN = re.compile(r"^chain\s+(\S+)\s*\{")


@dataclass
class Snapshot:
    policies: Dict[str, str] = field(default_factory=dict)
    chains: Set[str] = field(default_factory=set)  # base chains of the table that exist
    rules: Dict[str, List[Rule]] = field(default_factory=lambda: {c: [] for c in CHAINS})
    exists: bool = False  # the table itself


def words(line: str) -> List[str]:
    """Split a rule into words: a quoted string and a {set} stay in one piece (a set without blanks)."""
    out = []
    for m in _WORDS.finditer(line):
        word = m.group(0)
        if word.startswith("{"):
            word = "{" + re.sub(r"\s+", "", word[1:-1]) + "}"
        out.append(word)
    return out


def _service(word: str) -> str:
    if word.isdigit():
        return word
    try:
        return str(socket.getservbyname(word))
    except OSError:
        return word


def _ports(value: str) -> str:
    """`ssh`, `{80,https}`, `1000-2000` -> numbers, in the same shape."""
    inner = value[1:-1] if value.startswith("{") else value
    out = ",".join("-".join(_service(x) for x in item.split("-")) for item in inner.split(","))
    return "{" + out + "}" if value.startswith("{") else out


def _display_port(value: str) -> str:
    inner = value[1:-1] if value.startswith("{") else value
    return inner.replace("-", ":")


def _address(value: str) -> str:
    if value == "0.0.0.0/0":
        return ""
    return value[:-3] if value.endswith("/32") else value


def _strip(words_: List[str], marker: str, take: int) -> Tuple[List[str], List[str]]:
    """Cut `marker` and the `take` words after it out of the list; returns (rest, the cut words)."""
    if marker in words_:
        i = words_.index(marker)
        return words_[:i] + words_[i + 1 + take:], words_[i + 1:i + 1 + take]
    return words_, []


def parse_rule(chain: str, index: int, line: str) -> Rule:
    toks = words(line)
    toks, comment = _strip(toks, "comment", 1)
    tag = comment[0].strip('"') if comment else ""
    pkts = nbytes = 0
    if "counter" in toks:
        i = toks.index("counter")
        if toks[i + 1:i + 5:2] == ["packets", "bytes"]:
            pkts, nbytes = int(toks[i + 2]), int(toks[i + 4])
            del toks[i:i + 5]
        else:
            del toks[i]

    # the verdict: the first of the known ones; `reject with ...` keeps its tail
    verdict_at = next((i for i, t in enumerate(toks) if t in VERDICTS), None)
    action = toks[verdict_at] if verdict_at is not None else "-"
    enabled = True
    log = False
    if tag.startswith(OFF_TAG + ":") and action == "continue":
        parts = tag.split(":")
        action, enabled, log = parts[2], False, "log" in parts[3:]
        toks[verdict_at] = action

    protocol, source, destination, sport, dport = "all", "", "", "", ""
    spec: List[str] = []
    extra: List[str] = []
    body = toks if verdict_at is None else toks[:verdict_at]
    tail = [] if verdict_at is None else toks[verdict_at:]
    i = 0
    while i < len(body):
        tok = body[i]
        nxt = body[i + 1] if i + 1 < len(body) else ""
        arg = body[i + 2] if i + 2 < len(body) else ""
        if tok == "ip" and nxt == "protocol" and arg and arg != "!=":
            protocol = _PROTOCOLS.get(arg, arg)
            spec += ["ip", "protocol", protocol]
            i += 3
        elif tok == "meta" and nxt == "l4proto" and arg and arg != "!=":
            protocol = _PROTOCOLS.get(arg, arg)
            spec += ["ip", "protocol", protocol]
            i += 3
        elif tok in ("tcp", "udp") and nxt in ("dport", "sport") and arg and arg != "!=":
            protocol = tok
            value = _ports(arg)
            if nxt == "dport":
                dport = _display_port(value)
            else:
                sport = _display_port(value)
            spec += [tok, nxt, value]
            i += 3
        elif tok == "ip" and nxt in ("saddr", "daddr") and arg and arg != "!=":
            if nxt == "saddr":
                source = _address(arg)
            else:
                destination = _address(arg)
            spec += ["ip", nxt, arg]
            i += 3
        else:
            extra.append(tok)
            spec.append(tok)
            i += 1
    spec += tail
    if tail[:1] == ["reject"] and len(tail) > 1:
        extra.append("reject-with")  # a reject with options does not fit the dialog

    port = f"sp:{sport} dp:{dport}" if sport and dport else f"sp:{sport}" if sport else dport
    # the hidden rules keep every word in `spec`; their columns are not shown anyway
    return Rule(
        chain=chain,
        index=index,
        pkts=pkts,
        bytes=nbytes,
        protocol=protocol,
        source=source,
        destination=destination,
        port=port,
        action=action,
        enabled=enabled,
        spec=tuple(spec),
        extra=tuple(extra),
        log=log,
        tag=tag,
    )


def parse_listing(text: Optional[str]) -> Snapshot:
    """Parse `nft list table ip linfw` (None: there is no such table)."""
    snap = Snapshot()
    if text is None:
        return snap
    snap.exists = True
    current: Optional[str] = None
    in_set = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("set ") and line.endswith("{"):
            in_set = True
            continue
        m = _CHAIN.match(line)
        if m:
            in_set = False
            name = m.group(1).upper()
            current = name if name in CHAINS else None
            if current:
                snap.chains.add(current)
            continue
        if line == "}":
            in_set = False
            current = None if current is None else current
            continue
        if in_set or current is None or line.startswith("table "):
            continue
        if line.startswith("type "):
            policy = _POLICY.search(line)
            if policy:
                snap.policies[current] = policy.group(1).upper()
            continue
        rules = snap.rules[current]
        rules.append(parse_rule(current, len(rules) + 1, line))
    for rules in snap.rules.values():
        shown = 0
        for i, rule in enumerate(rules):
            if not rule.hidden:
                shown += 1
                twin = i > 0 and rules[i - 1].is_log
                rules[i] = replace(rule, number=shown, log=rule.log or twin)
    return snap


__all__ = ["Snapshot", "parse_listing", "parse_rule", "words", "VERDICTS", "RULE_TAG", "BASE_TAG", "LOG_TAG"]
