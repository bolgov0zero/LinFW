"""Address lists, stored as ipset sets (type hash:net, IPv4).

A list called `office` is the kernel set `lf_office`; the prefix keeps LinFW's
sets apart from any others on the machine (fail2ban, docker ...). A rule uses a
list as `-m set --match-set lf_office src|dst` and the interface writes that as
`@office`. Changing a list's contents takes effect in every rule that uses it at
once, no rule is rewritten.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Tuple

LIST_PREFIX = "lf_"
MAX_NAME = 28  # ipset names are limited to 31 characters
MAX_ELEMENTS = 262144
_NAME = re.compile(rf"^[A-Za-z][A-Za-z0-9_.-]{{0,{MAX_NAME - 1}}}$")
REF = re.compile(rf"^@([A-Za-z][A-Za-z0-9_.-]{{0,{MAX_NAME - 1}}})$")


def set_name(name: str) -> str:
    return LIST_PREFIX + name


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
    """An IPv4 address or network as ipset prints it (a /32 is just the address)."""
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


def sort_entries(entries: Iterable[str]) -> List[str]:
    return sorted(entries, key=lambda e: (int(ipaddress.IPv4Network(e, strict=False).network_address), e))


def parse_save(text: str) -> Dict[str, List[str]]:
    """`ipset save` output -> {list name: sorted entries}, our lists only."""
    result: Dict[str, List[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith(LIST_PREFIX):
            continue
        name = parts[1][len(LIST_PREFIX):]
        if parts[0] == "create":
            result.setdefault(name, [])
        elif parts[0] == "add" and len(parts) >= 3:
            result.setdefault(name, []).append(parts[2])
    return {name: sort_entries(entries) for name, entries in sorted(result.items())}
