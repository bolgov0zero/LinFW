"""Turn rules back into nft text: the commands that rewrite a chain, and the file that is
loaded at boot."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .model import (
    BASE_TAG,
    CHAINS,
    FAMILY,
    LOG_TAG,
    OFF_TAG,
    RULE_TAG,
    TABLE,
    Rule,
    base_spec,
)
from .parser import Snapshot

# the first of these words ends the matches of a rule: the counter goes right before it
_STATEMENTS = ("accept", "drop", "reject", "continue", "limit", "log", "return")
_HOOKS = {"INPUT": "input", "OUTPUT": "output", "FORWARD": "forward"}


def tag_of(rule: Rule) -> str:
    if rule.base_id:
        return rule.base_id
    if rule.is_log:
        return LOG_TAG
    if rule.enabled:
        return RULE_TAG
    return f"{OFF_TAG}:{rule.action}" + (":log" if rule.log else "")


def rule_words(
    spec: List[str], tag: str, counter: Optional[Tuple[int, int]] = None, off: bool = False
) -> str:
    """One rule as nft text. `off` replaces the verdict by `continue`; `counter` carries the numbers on."""
    cut = next((i for i, w in enumerate(spec) if w in _STATEMENTS), len(spec))
    head, tail = list(spec[:cut]), list(spec[cut:])
    if off:
        tail = ["continue"]
    stmt = ["counter"] if counter is None else ["counter", "packets", str(counter[0]), "bytes", str(counter[1])]
    return " ".join(head + stmt + tail + ["comment", f'"{tag}"'])


def rule_text(rule: Rule, with_counters: bool = True) -> str:
    spec = base_spec(rule.chain, rule.base_id) if rule.base_id else list(rule.spec)
    return rule_words(spec, tag_of(rule), (rule.pkts, rule.bytes) if with_counters else None, off=not rule.enabled and not rule.is_log)


def chain_decl(chain: str, policy: str = "accept") -> str:
    return f"{{ type filter hook {_HOOKS[chain]} priority filter; policy {policy.lower()}; }}"


def chain_commands(chain: str, rules: List[Rule], snap: Snapshot) -> List[str]:
    """Commands that make `chain` hold exactly `rules`: create it if needed, empty it, fill it.
    Sent as one transaction, so no packet ever sees a half-written chain."""
    name = chain.lower()
    lines: List[str] = []
    if chain not in snap.chains:
        lines.append(f"add chain {FAMILY} {TABLE} {name} {chain_decl(chain, snap.policies.get(chain, 'accept'))}")
    lines.append(f"flush chain {FAMILY} {TABLE} {name}")
    lines += [f"add rule {FAMILY} {TABLE} {name} {rule_text(r)}" for r in rules]
    return lines


def table_line() -> str:
    """Creates the table when it is missing and does nothing when it is there."""
    return f"table {FAMILY} {TABLE}"


def ruleset_text(snap: Snapshot, sets: Dict[str, List[str]]) -> str:
    """The whole table as a file `nft -f` loads: it replaces the table in one step.
    Counters are left at zero: after a reboot the kernel counts from zero anyway."""
    out = [f"table {FAMILY} {TABLE}", f"delete table {FAMILY} {TABLE}", f"table {FAMILY} {TABLE} {{"]
    for name, entries in sets.items():
        out.append(f"\tset {name} {{")
        out += ["\t\ttype ipv4_addr", "\t\tflags interval"]
        if entries:
            out.append(f"\t\telements = {{ {', '.join(entries)} }}")
        out.append("\t}")
    for chain in CHAINS:
        out.append(f"\tchain {chain.lower()} {{")
        out.append(f"\t\ttype filter hook {_HOOKS[chain]} priority filter; policy {snap.policies.get(chain, 'ACCEPT').lower()};")
        out += [f"\t\t{rule_text(r, with_counters=False)}" for r in snap.rules[chain]]
        out.append("\t}")
    out.append("}")
    return "\n".join(out) + "\n"


__all__ = ["rule_text", "rule_words", "chain_commands", "table_line", "ruleset_text", "chain_decl", "tag_of", "BASE_TAG"]
