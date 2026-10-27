from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field, replace
from typing import Dict, List, Sequence, Set

from .model import CHAINS, OFF_PREFIX, Rule

_COUNTERS = re.compile(r"^\[(\d+):(\d+)\]\s+(.*)$")

_PORT_DST = {"--dport", "--destination-port", "--dports", "--destination-ports"}
_PORT_SRC = {"--sport", "--source-port", "--sports", "--source-ports"}
# modules implied by the protocol / port columns
_IMPLIED_MODULES = {"tcp", "udp", "icmp", "multiport"}


@dataclass
class Snapshot:
    policies: Dict[str, str] = field(default_factory=dict)
    chains: Set[str] = field(default_factory=set)
    rules: Dict[str, List[Rule]] = field(default_factory=lambda: {c: [] for c in CHAINS})


def _address(value: str) -> str:
    if value == "0.0.0.0/0":
        return ""
    return value[:-3] if value.endswith("/32") else value


def parse_rule(chain: str, index: int, pkts: int, nbytes: int, tokens: Sequence[str]) -> Rule:
    protocol, source, destination, sport, dport, target = "all", "", "", "", "", ""
    extra: List[str] = []
    negate = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        arg = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok == "!":
            negate = True
            i += 1
            continue
        bang = "!" if negate else ""
        negate = False
        step = 2
        if tok in ("-p", "--protocol"):
            protocol = bang + arg
        elif tok in ("-s", "--source"):
            source = bang + _address(arg)
        elif tok in ("-d", "--destination"):
            destination = bang + _address(arg)
        elif tok in _PORT_DST:
            dport = bang + arg
        elif tok in _PORT_SRC:
            sport = bang + arg
        elif tok in ("-j", "--jump", "-g", "--goto"):
            target = arg
        elif tok == "--reject-with":
            pass
        elif tok == "-m" and arg in _IMPLIED_MODULES:
            pass
        elif tok == "-m":
            extra += [bang, "-m", arg] if bang else ["-m", arg]
        else:
            if bang:
                extra.append("!")
            extra.append(tok)
            step = 1
        i += step

    enabled = not target.startswith(OFF_PREFIX)
    action = (target if enabled else target[len(OFF_PREFIX):]).lower() or "-"
    if sport and dport:
        port = f"sp:{sport} dp:{dport}"
    elif sport:
        port = f"sp:{sport}"
    else:
        port = dport
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
        spec=tuple(tokens),
        extra=tuple(extra),
    )


def parse_save(text: str) -> Snapshot:
    """Parse `iptables-save -c -t filter` output."""
    snap = Snapshot()
    in_filter = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            in_filter = line == "*filter"
            continue
        if line == "COMMIT":
            in_filter = False
            continue
        if not in_filter:
            continue
        if line.startswith(":"):
            name, policy = line[1:].split()[:2]
            snap.chains.add(name)
            if name in CHAINS:
                snap.policies[name] = policy
            continue
        pkts = nbytes = 0
        m = _COUNTERS.match(line)
        if m:
            pkts, nbytes, line = int(m.group(1)), int(m.group(2)), m.group(3)
        tokens = shlex.split(line)
        if len(tokens) < 2 or tokens[0] != "-A" or tokens[1] not in CHAINS:
            continue
        rules = snap.rules[tokens[1]]
        rules.append(parse_rule(tokens[1], len(rules) + 1, pkts, nbytes, tokens[2:]))
    for rules in snap.rules.values():
        shown = 0
        for i, rule in enumerate(rules):
            if not rule.hidden:
                shown += 1
                twin = i > 0 and rules[i - 1].is_log
                rules[i] = replace(rule, number=shown, log=twin)
    return snap
