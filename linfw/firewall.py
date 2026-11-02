from __future__ import annotations

import ipaddress
import subprocess
from contextlib import nullcontext
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from . import journal, lists as lst, persist
from .counters import CounterStore, assign_keys, signature, store_key
from .journal import LogEntry
from .model import (
    ACTIONS,
    BASE_TAG,
    CHAINS,
    FAMILY,
    LOG_TAG,
    RULE_TAG,
    TABLE,
    FirewallError,
    NewRule,
    Rule,
    base_ids,
    base_spec,
    log_tokens,
)
from .parser import Snapshot, parse_listing
from .render import chain_commands, rule_text, ruleset_text, table_line


def _clean_error(text: str) -> str:
    """`/dev/stdin:3:9-12: Error: No such file or directory` + source echo -> the message alone."""
    for line in text.splitlines():
        if "Error:" in line:
            return line.split("Error:", 1)[1].strip()
    return text.strip().splitlines()[0] if text.strip() else ""


class SystemRunner:
    """Talks to the real nft."""

    def __init__(self) -> None:
        self.nft_binary = persist.find_binary("nft")
        if not self.nft_binary:
            raise FirewallError("nft не найден. Установите пакет nftables.")

    def _run(self, argv: List[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            raise FirewallError("nft не ответил за 15 секунд") from None

    def list_table(self) -> Optional[str]:
        """`nft list table ip linfw`; None when the table does not exist yet."""
        r = self._run([self.nft_binary, "list", "table", FAMILY, TABLE])
        if r.returncode:
            message = _clean_error(r.stderr or r.stdout)
            if "No such file or directory" in message:
                return None
            raise FirewallError(message or f"nft завершился с кодом {r.returncode}")
        return r.stdout

    def nft(self, lines: List[str]) -> None:
        """Run the commands as one transaction: all of them take effect or none."""
        r = self._run([self.nft_binary, "-f", "-"], "\n".join(lines) + "\n")
        if r.returncode:
            raise FirewallError(_clean_error(r.stderr or r.stdout) or f"nft завершился с кодом {r.returncode}")

    def problem(self) -> Optional[str]:
        """Why nftables cannot be used here, or None if it can."""
        r = self._run([self.nft_binary, "list", "tables"])
        return _clean_error(r.stderr or r.stdout) or "nft недоступен" if r.returncode else None

    def persist(self, text: str) -> str:
        return persist.save(text)

    def persist_info(self) -> Optional[str]:
        return persist.describe()

    def read_journal(self, chain: Optional[str] = None, actions=None, limit: int = journal.MAX_ENTRIES) -> Tuple[str, List[LogEntry]]:
        return journal.read_entries(chain, actions, limit)

    def logd_state(self) -> Optional[str]:
        """systemd's view of linfw-logd ("active", "inactive", "failed" ...), None without systemd."""
        systemctl = persist.find_binary("systemctl")
        if not systemctl:
            return None
        try:
            r = subprocess.run([systemctl, "is-active", "linfw-logd"], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r.stdout.strip() or "unknown"


def _blocks(rules: List[Rule]) -> List[List[Rule]]:
    """The chain as logical blocks: a log twin goes together with the rule below it."""
    blocks: List[List[Rule]] = []
    for rule in rules:
        if blocks and blocks[-1][-1].is_log:
            blocks[-1].append(rule)
        else:
            blocks.append([rule])
    return blocks


def _flat(blocks: List[List[Rule]]) -> List[Rule]:
    return [r for block in blocks for r in block]


class Firewall:
    """Rule operations. Every mutation re-reads the table first and refuses to act if the
    rule is no longer where the UI last saw it. A chain is changed by rewriting it
    (counters carried over) in one nft transaction.

    A rule with logging on is a *block* of two rules: the hidden log twin directly above it,
    then the rule itself. Every operation below keeps the two together."""

    def __init__(self, runner, counters: Optional[CounterStore] = None) -> None:
        self.runner = runner
        self.counters = counters  # running totals that survive resets of the kernel counters

    def snapshot(self) -> Snapshot:
        return parse_listing(self.runner.list_table())

    def persist(self) -> str:
        text = self.runner.list_table()
        snap = parse_listing(text)
        return self.runner.persist(ruleset_text(snap, lst.parse_sets(text or "")))

    def persist_info(self) -> Optional[str]:
        return self.runner.persist_info()

    def read_journal(self, chain: Optional[str] = None, actions=None, limit: int = journal.MAX_ENTRIES) -> Tuple[str, List[LogEntry]]:
        return self.runner.read_journal(chain, actions, limit)

    # -- address lists ----------------------------------------------------

    def lists_overview(self) -> Tuple[Dict[str, int], Optional[str]]:
        """({name: number of addresses}, None) or ({}, the reason lists cannot be used)."""
        try:
            return {n: len(e) for n, e in self.lists().items()}, None
        except FirewallError as exc:
            return {}, str(exc)

    def lists_problem(self) -> Optional[str]:
        return self.runner.problem()

    def lists_persistent(self) -> bool:
        """Lists are saved in the same file as the rules."""
        return self.runner.persist_info() is not None

    def lists(self) -> Dict[str, List[str]]:
        """{name: entries} of LinFW's lists."""
        return lst.parse_sets(self.runner.list_table() or "")

    def list_usage(self, snap: Optional[Snapshot] = None) -> Dict[str, List[str]]:
        """{name: ["INPUT #3", ...]}: which rules use each list."""
        snap = snap or self.snapshot()
        usage: Dict[str, List[str]] = {}
        for chain in CHAINS:
            for rule in snap.rules[chain]:
                if rule.hidden:
                    continue
                for value in (rule.source, rule.destination):
                    name = lst.list_ref(value)
                    if name:
                        usage.setdefault(name, []).append(f"{chain} #{rule.number}")
        return usage

    def create_list(self, name: str) -> None:
        name = lst.check_name(name)
        if name in self.lists():
            raise FirewallError(f"Список «{name}» уже есть")
        self.runner.nft([table_line(), f"add set {FAMILY} {TABLE} {name} {{ type ipv4_addr; flags interval; }}"])

    def delete_list(self, name: str) -> None:
        used = self.list_usage().get(name)
        if used:
            raise FirewallError(f"Список «{name}» используется в правилах: {', '.join(used)}. Сначала измените или удалите их.")
        self.runner.nft([f"delete set {FAMILY} {TABLE} {name}"])

    def add_to_list(self, name: str, entries: List[str]) -> int:
        """Add already validated entries; returns how many were added.

        A set of intervals refuses elements that overlap, so an address that is already
        covered by a network in the list (or in this batch) is not added, and a network that
        covers addresses already in the list takes their place."""
        have = self.lists().get(name, [])
        nets = {e: ipaddress.IPv4Network(e, strict=False) for e in have if "-" not in e}
        kept: Dict[str, ipaddress.IPv4Network] = {}
        for entry in sorted(dict.fromkeys(lst.normalize_entry(e) for e in entries), key=lambda e: int(e.partition("/")[2] or 32)):
            net = ipaddress.IPv4Network(entry, strict=False)
            if not any(net.subnet_of(other) for other in [*nets.values(), *kept.values()]):
                kept[entry] = net
        covered = [e for e, n in nets.items() if any(n.subnet_of(k) for k in kept.values())]
        lines = []
        if covered:
            lines.append(f"delete element {FAMILY} {TABLE} {name} {{ {', '.join(covered)} }}")
        if kept:
            lines.append(f"add element {FAMILY} {TABLE} {name} {{ {', '.join(kept)} }}")
            self.runner.nft(lines)
        return len(kept)

    def remove_from_list(self, name: str, entries: List[str]) -> None:
        present = [e for e in dict.fromkeys(entries) if e in self.lists().get(name, [])]
        if present:
            self.runner.nft([f"delete element {FAMILY} {TABLE} {name} {{ {', '.join(present)} }}"])

    def _check_lists(self, new: NewRule) -> None:
        wanted = new.used_lists()
        if wanted:
            existing = self.lists()
            for name in wanted:
                if name not in existing:
                    raise FirewallError(f"Список «{name}» не найден: создайте его в окне «Списки» (F8)")

    def counter_totals(self, snap: Snapshot) -> Dict[str, Tuple[int, int]]:
        """{"CHAIN:index": (packets, bytes)} counted since the rule was first seen,
        regardless of resets. Empty if the totals cannot be kept (the UI then shows
        the kernel's own numbers)."""
        if not self.counters:
            return {}
        try:
            return self.counters.update(snap)
        except OSError:
            return {}

    def _store_key(self, snap: Snapshot, rule: Rule) -> Optional[str]:
        found = assign_keys(snap).get(rule.key)
        return found[0] if found else None

    def log_diagnosis(self) -> Tuple[int, int, Optional[str]]:
        """(rules with logging on, packets their twins have sent to the log, state of
        linfw-logd). Packets > 0 with an empty journal means the service is not
        recording; packets == 0 means the rules simply have not matched."""
        twins = [r for rules in self.snapshot().rules.values() for r in rules if r.is_log]
        return len(twins), sum(r.pkts for r in twins), self.runner.logd_state()

    # -- building blocks of the changes ----------------------------------

    @staticmethod
    def _fresh(chain: str, index: int, spec: List[str], tag: str, action: str, enabled: bool = True, log: bool = False) -> Rule:
        """A rule that has just been made: counters at zero, columns not needed (only the text is written)."""
        return Rule(chain, index, 0, 0, "all", "", "", "", action, enabled, tuple(spec), (), 0, log, tag)

    def _block_for(self, chain: str, new: NewRule, enabled: bool, counters: Optional[Tuple[int, int]] = None) -> List[Rule]:
        action = new.action.lower()
        main = self._fresh(chain, 0, new.to_spec(), RULE_TAG if enabled else f"linfw:off:{action}" + (":log" if new.log else ""),
                           action, enabled, new.log)
        if counters:
            main = replace(main, pkts=counters[0], bytes=counters[1])
        if new.log and enabled:
            return [self._fresh(chain, 0, new.to_log_spec(), LOG_TAG, "log"), main]
        return [main]

    def _write(self, snap: Snapshot, changes: Dict[str, List[Rule]]) -> None:
        """Rewrite the chains in `changes` (and create the table and chains if missing), in one transaction."""
        lines = [table_line()]
        for chain, rules in changes.items():
            lines += chain_commands(chain, rules, snap)
        self.runner.nft(lines)

    def _current(self, rule: Rule) -> Tuple[Snapshot, List[Rule]]:
        snap = self.snapshot()
        rules = snap.rules[rule.chain]
        if rule.index > len(rules) or rules[rule.index - 1].spec != rule.spec or rules[rule.index - 1].tag != rule.tag:
            raise FirewallError("Правила изменились снаружи — список обновлён, повторите действие")
        return snap, rules

    @staticmethod
    def _refuse_hidden(rule: Rule) -> None:
        if rule.hidden:
            raise FirewallError("Служебные правила нельзя изменять")

    @staticmethod
    def _block_of(blocks: List[List[Rule]], rule: Rule) -> int:
        return next(i for i, b in enumerate(blocks) if any(r.index == rule.index for r in b))

    # -- rule operations -------------------------------------------------

    def add(self, new: NewRule) -> None:
        new = new.validated()
        self._check_lists(new)
        snap = self.snapshot()
        block = self._block_for(new.chain, new, True)
        if new.chain not in snap.chains:  # no table yet: make it, with the new rule in it
            self._write(snap, {new.chain: snap.rules[new.chain] + block})
        else:  # appending needs no rewrite: the other rules are not touched
            self.runner.nft([f"add rule {FAMILY} {TABLE} {new.chain.lower()} {rule_text(r)}" for r in block])

    def edit(self, rule: Rule, new: NewRule) -> None:
        """Replace a rule in place (same chain, same position, same on/off state).
        Its running total follows it to the new definition."""
        snap, rules = self._current(rule)
        self._refuse_hidden(rule)
        new = new.validated()
        self._check_lists(new)
        if new.chain != rule.chain:
            raise FirewallError("Цепочку существующего правила изменить нельзя")
        blocks = _blocks(rules)
        at = self._block_of(blocks, rule)
        blocks[at] = self._block_for(rule.chain, new, rule.enabled)
        # the total follows the rule; the lock keeps the sampler out until the kernel counter has restarted
        with self.counters.locked() if self.counters else nullcontext():
            moved = self._move_total(snap, rule, new.to_spec())
            try:
                self._write(snap, {rule.chain: _flat(blocks)})
            except FirewallError:
                if moved:
                    self.counters.restore(*moved)
                raise

    def delete(self, rule: Rule) -> None:
        snap, rules = self._current(rule)
        self._refuse_hidden(rule)
        key = self._store_key(snap, rule) if self.counters else None
        blocks = _blocks(rules)
        del blocks[self._block_of(blocks, rule)]
        self._write(snap, {rule.chain: _flat(blocks)})
        if key:
            self.counters.forget(key)

    def move(self, rule: Rule, delta: int) -> bool:
        """Move a rule (with its log twin) one step up (-1) or down (+1). The chain is rewritten
        in one transaction, so there is never a moment without the rule. Counters are carried over."""
        snap, rules = self._current(rule)
        self._refuse_hidden(rule)
        blocks = _blocks(rules)
        at = self._block_of(blocks, rule)
        other = at + delta
        if other < 0 or other >= len(blocks):
            return False
        if blocks[other][-1].base_id:  # never above the base rules at the top of the chain
            return False
        blocks[at], blocks[other] = blocks[other], blocks[at]
        self._write(snap, {rule.chain: _flat(blocks)})
        return True

    def toggle(self, rule: Rule) -> bool:
        """Enable/disable a rule in place (its log twin follows). Returns the new
        enabled state."""
        snap, rules = self._current(rule)
        self._refuse_hidden(rule)
        action = rule.action.upper()
        if action not in ACTIONS:
            raise FirewallError(f"Правило с действием {action} нельзя выключить")
        enable = not rule.enabled
        blocks = _blocks(rules)
        at = self._block_of(blocks, rule)
        main = replace(blocks[at][-1], enabled=enable, log=rule.log)
        block = [main]
        if enable and rule.log:
            # the twin is made again from the rule's own matches
            matches = list(rule.spec[:-1])
            block.insert(0, self._fresh(rule.chain, 0, matches + log_tokens(rule.chain, rule.action), LOG_TAG, "log"))
        blocks[at] = block
        self._write(snap, {rule.chain: _flat(blocks)})
        return enable

    # -- base rules ------------------------------------------------------

    @staticmethod
    def _chain_base_ok(chain: str, rules: List[Rule]) -> bool:
        want = base_ids(chain)
        return [r.base_id for r in rules[: len(want)]] == want and not any(
            r.base_id for r in rules[len(want):]
        )

    def base_ok(self, snap: Snapshot) -> bool:
        return snap.exists and all(c in snap.chains and self._chain_base_ok(c, snap.rules[c]) for c in CHAINS)

    def ensure_base(self) -> bool:
        """Create the table, put the base rules (loopback, established/related) at the top of every
        chain. Returns True if anything had to be changed. All chains are written in one
        transaction, so traffic is never left unprotected."""
        snap = self.snapshot()
        changes: Dict[str, List[Rule]] = {}
        for chain in CHAINS:
            if chain in snap.chains and self._chain_base_ok(chain, snap.rules[chain]):
                continue
            have = {r.base_id: r for r in snap.rules[chain] if r.base_id}
            base = []
            for tag in base_ids(chain):
                old = have.get(tag)
                base.append(self._fresh(chain, 0, base_spec(chain, tag), tag, "accept") if old is None else old)
            changes[chain] = base + [r for r in snap.rules[chain] if not r.base_id]
        if changes:
            self._write(snap, changes)
        return bool(changes)

    def remove_base(self) -> bool:
        snap = self.snapshot()
        changes = {
            chain: [r for r in snap.rules[chain] if not r.base_id]
            for chain in CHAINS
            if any(r.base_id for r in snap.rules[chain])
        }
        if changes:
            self._write(snap, changes)
        return bool(changes)

    # -- helpers ---------------------------------------------------------

    def _move_total(self, snap: Snapshot, rule: Rule, new_spec: List[str]) -> Optional[Tuple[str, str, Dict]]:
        """Before a rule is rewritten, hand its running total to the new definition
        (the kernel counter restarts at zero, the total must not).
        Returns (old key, new key, displaced entry) for a rollback."""
        if not self.counters:
            return None
        old_key = self._store_key(snap, rule)
        if not old_key:
            return None
        sig = signature(new_spec)
        above = sum(
            1 for r in snap.rules[rule.chain] if not r.hidden and r.index < rule.index and signature(r.spec) == sig
        )
        new_key = store_key(rule.chain, sig, above)
        try:
            self.counters.update(snap)  # take what the old rule counted up to now
            entry = self.counters.rebase(old_key, new_key)
        except OSError:
            return None
        return (old_key, new_key, entry) if entry else None


__all__ = ["Firewall", "SystemRunner", "BASE_TAG"]
