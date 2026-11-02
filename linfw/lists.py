"""Address lists, stored as nftables sets (type ipv4_addr, interval).

A list called `office` is the set `office` of LinFW's own table; a rule uses it as
`ip saddr @office` / `ip daddr @office` and the interface writes that as `@office`.
Changing a list's contents takes effect in every rule that uses it at once, no rule
is rewritten.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Tuple

MAX_NAME = 28
_NAME = re.compile(rf"^[A-Za-z][A-Za-z0-9_.-]{{0,{MAX_NAME - 1}}}$")
REF = re.compile(rf"^@([A-Za-z][A-Za-z0-9_.-]{{0,{MAX_NAME - 1}}})$")
_SET = re.compile(r"^set\s+(\S+)\s*\{")


def check_name(name: str) -> str:
    """The list name, or ValueError with a Russian message."""
    name = name.strip()
    if not _NAME.match(name):
        raise ValueError(
            f"Название списка: латиница, цифры, «_», «-», «.», начинается с буквы, до {MAX_NAME} символов"
        )
    return name


def list_ref(value: str):
    """`@office` -> `office`, anything else -> None."""
    m = REF.match(value.strip())
    return m.group(1) if m else None


def normalize_entry(text: str) -> str:
    """An IPv4 address or network as nft prints it (a /32 is just the address)."""
    text = text.strip()
    try:
        net = ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        raise ValueError(f"«{text}»: нужен IPv4-адрес или сеть (например 10.0.0.5 или 10.0.0.0/24)") from None
    if net.prefixlen == 0:
        raise ValueError("Сеть /0 (все адреса) в список добавить нельзя")
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def parse_entries(text: str) -> Tuple[List[str], List[str]]:
    """Split pasted text (lines, spaces, commas, semicolons) into (valid entries, error messages)."""
    good: List[str] = []
    errors: List[str] = []
    for token in re.split(r"[\s,;]+", text.strip()):
        if not token:
            continue
        try:
            entry = normalize_entry(token)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if entry not in good:
            good.append(entry)
    return good, errors


def _first_address(entry: str) -> int:
    """The first address of an entry: `10.0.0.5`, `10.0.0.0/24` or a range `10.0.0.1-10.0.0.9`."""
    head = entry.split("-", 1)[0].split("/", 1)[0]
    try:
        return int(ipaddress.IPv4Address(head))
    except ValueError:
        return 0


def sort_entries(entries: Iterable[str]) -> List[str]:
    return sorted(entries, key=lambda e: (_first_address(e), e))


def parse_sets(text: str) -> Dict[str, List[str]]:
    """The sets in a listing of the table -> {list name: sorted entries}."""
    result: Dict[str, List[str]] = {}
    name = None
    gathering = False
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        m = _SET.match(line)
        if m:
            name = m.group(1)
            result.setdefault(name, [])
            continue
        if name is None:
            continue
        if gathering or line.startswith("elements"):
            buffer += " " + line
            gathering = "}" not in line
            if not gathering:
                body = buffer[buffer.index("{") + 1:buffer.rindex("}")]
                result[name] = sort_entries(e.strip() for e in body.split(",") if e.strip())
                buffer = ""
            continue
        if line == "}":
            name = None
    return {n: result[n] for n in sorted(result)}
