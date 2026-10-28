from __future__ import annotations

import subprocess
from contextlib import nullcontext
from typing import Dict, List, Optional, Tuple

from . import journal, persist
from .counters import CounterStore, assign_keys, signature, store_key
from .journal import LogEntry
from .model import (
    CHAINS,
    OFF_CHAINS,
    OFF_PREFIX,
    ACTIONS,
    FirewallError,
    NewRule,
    Rule,
    base_ids,
    base_specs,
    nflog_target,
)
from .parser import Snapshot, parse_save


class SystemRunner:
    """Talks to the real iptables."""

    def __init__(self) -> None:
        self.iptables = persist.find_binary("iptables")
        self.iptables_save = persist.find_binary("iptables-save")
        if not (self.iptables and self.iptables_save):
            raise FirewallError("iptables не найден. Установите пакет iptables.")

    def _run(self, argv: List[str]) -> str:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            raise FirewallError("iptables не ответил за 15 секунд") from None
        if r.returncode:
            raise FirewallError((r.stderr or r.stdout).strip() or f"iptables завершился с кодом {r.returncode}")
        return r.stdout

    def ipt(self, args: List[str]) -> None:
        self._run([self.iptables, "-w", *args])

    def save_text(self) -> str:
        return self._run([self.iptables_save, "-c", "-t", "filter"])

    def persist(self) -> str:
        return persist.save(self._run([self.iptables_save]))

    def persist_info(self) -> Optional[str]:
        return persist.describe()

    def read_journal(self, chain: Optional[str] = None, actions=None) -> Tuple[str, List[LogEntry]]:
        return journal.read_entries(chain, actions)

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


class Firewall:
    """Rule operations. Every mutation re-reads the chain first and refuses to
    act if the rule is no longer where the UI last saw it.

    A rule with logging on is a *block* of two iptables rules: the hidden LOG
    twin directly above it, then the rule itself. Every operation below keeps
    the two together."""

    def __init__(self, runner, counters: Optional[CounterStore] = None) -> None:
        self.runner = runner
        self.counters = counters  # running totals that survive resets of the kernel counters

    def snapshot(self) -> Snapshot:
        return parse_save(self.runner.save_text())

    def persist(self) -> str:
        return self.runner.persist()

    def persist_info(self) -> Optional[str]:
        return self.runner.persist_info()

    def read_journal(self, chain: Optional[str] = None, actions=None) -> Tuple[str, List[LogEntry]]:
        return self.runner.read_journal(chain, actions)

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

    # -- rule operations -------------------------------------------------

    def add(self, new: NewRule) -> None:
        new = new.validated()
        if new.log:
            self.runner.ipt(["-A", new.chain, *new.to_log_spec()])
        self.runner.ipt(["-A", new.chain, *new.to_spec()])

    def edit(self, rule: Rule, new: NewRule) -> None:
        """Replace a rule in place (same chain, same position, same on/off state).
        Counters start from zero since it is, in effect, a different rule."""
        rules = self._current(rule)
        self._refuse_hidden(rule)
        new = new.validated()
        if new.chain != rule.chain:
            raise FirewallError("Цепочку существующего правила изменить нельзя")
        spec = new.to_spec()
        if not rule.enabled:
            self._ensure_off_chains()
            spec[-1] = OFF_PREFIX + new.action
        n = rule.index
        had_twin = self._has_twin(rules, n)
        # the total follows the rule; the lock keeps the sampler out until the kernel counter has restarted
        with self.counters.locked() if self.counters else nullcontext():
            moved = self._move_total(rule, spec)
            try:
                self.runner.ipt(["-R", rule.chain, str(n), *spec])
            except FirewallError:
                if moved:
                    self.counters.restore(*moved)
                raise
        if new.log and had_twin:
            self.runner.ipt(["-R", rule.chain, str(n - 1), *new.to_log_spec(rule.enabled)])
        elif new.log:
            self.runner.ipt(["-I", rule.chain, str(n), *new.to_log_spec(rule.enabled)])
        elif had_twin:
            self.runner.ipt(["-D", rule.chain, str(n - 1)])

    def delete(self, rule: Rule) -> None:
        rules = self._current(rule)
        self._refuse_hidden(rule)
        start = self._block_start(rules, rule.index)
        key = self._store_key(self.snapshot(), rule) if self.counters else None
        for idx in range(rule.index, start - 1, -1):
            self.runner.ipt(["-D", rule.chain, str(idx)])
        if key:
            self.counters.forget(key)

    def move(self, rule: Rule, delta: int) -> bool:
        """Move a rule (with its log twin) one step up (-1) or down (+1). Copies
        are inserted before the originals are removed, so the chain never has a
        gap. Counters are carried over."""
        rules = self._current(rule)
        self._refuse_hidden(rule)
        n = rule.index
        start = self._block_start(rules, n)
        size = n - start + 1
        block = [self._with_counters(r) for r in rules[start - 1:n]]
        if delta < 0:
            above = start - 1  # last rule of the previous block
            # never go above the base rules at the top of the chain
            if above < 1 or rules[above - 1].base_id:
                return False
            target = self._block_start(rules, above)
            self._insert_block(rule.chain, target, len(rules), block)
            old = range(n + size, start + size - 1, -1)
        else:
            if n == len(rules):
                return False
            below = n + 1 if not rules[n].is_log else n + 2  # last rule of the next block
            self._insert_block(rule.chain, below + 1, len(rules), block)
            old = range(n, start - 1, -1)
        for idx in old:
            self.runner.ipt(["-D", rule.chain, str(idx)])
        return True

    def toggle(self, rule: Rule) -> bool:
        """Enable/disable a rule in place (its log twin follows). Returns the new
        enabled state."""
        rules = self._current(rule)
        self._refuse_hidden(rule)
        action = rule.action.upper()
        if action not in ACTIONS:
            raise FirewallError(f"Правило с действием {action} нельзя выключить")
        spec = list(rule.spec)
        j = self._target_index(spec)
        enable = not rule.enabled
        if not enable:
            self._ensure_off_chains()
            spec[j + 1] = OFF_PREFIX + action
            # --reject-with is only valid together with the REJECT target
            while "--reject-with" in spec:
                k = spec.index("--reject-with")
                del spec[k:k + 2]
        else:
            spec[j + 1] = action
        main = ["-R", rule.chain, str(rule.index), *spec, "-c", str(rule.pkts), str(rule.bytes)]
        if self._has_twin(rules, rule.index):
            twin = rules[rule.index - 2]
            twin_spec = self._twin_spec(twin, rule.chain, action, on=enable)
            self.runner.ipt(
                ["-R", rule.chain, str(rule.index - 1), *twin_spec, "-c", str(twin.pkts), str(twin.bytes)]
            )
        self.runner.ipt(main)
        return enable

    # -- base rules ------------------------------------------------------

    @staticmethod
    def _chain_base_ok(chain: str, rules: List[Rule]) -> bool:
        want = base_ids(chain)
        return [r.base_id for r in rules[: len(want)]] == want and not any(
            r.base_id for r in rules[len(want):]
        )

    @staticmethod
    def _legacy_twins(snap: Snapshot) -> List[Rule]:
        """Twins made by earlier versions with the LOG target (kernel log), now replaced by NFLOG."""
        return [
            r
            for rules in snap.rules.values()
            for r in rules
            if r.is_log and any(tok == "-j" and r.spec[i + 1] == "LOG" for i, tok in enumerate(r.spec[:-1]))
        ]

    def base_ok(self, snap: Snapshot) -> bool:
        return all(self._chain_base_ok(c, snap.rules[c]) for c in CHAINS) and not self._legacy_twins(snap)

    def _upgrade_legacy_twins(self, snap: Snapshot) -> bool:
        legacy = self._legacy_twins(snap)
        for twin in legacy:
            spec = list(twin.spec)
            j = self._target_index(spec)
            options = spec[j + 2:]
            prefix = options[options.index("--log-prefix") + 1] if "--log-prefix" in options else None
            spec = spec[:j] + nflog_target(twin.chain, "", prefix)
            self.runner.ipt(["-R", twin.chain, str(twin.index), *spec, "-c", str(twin.pkts), str(twin.bytes)])
        return bool(legacy)

    def ensure_base(self) -> bool:
        """Put the base rules (loopback, established/related) at the top of every
        chain, and move logging twins from the old LOG target to NFLOG. Returns
        True if anything had to be changed. New copies go in before stale ones are
        removed, so traffic is never left unprotected."""
        snap = self.snapshot()
        changed = self._upgrade_legacy_twins(snap)
        if changed:
            snap = self.snapshot()
        for chain in CHAINS:
            if self._chain_base_ok(chain, snap.rules[chain]):
                continue
            changed = True
            specs = base_specs(chain)
            for pos, spec in enumerate(specs, start=1):
                self.runner.ipt(["-I", chain, str(pos), *spec])
            stale = [r for r in self.snapshot().rules[chain] if r.base_id and r.index > len(specs)]
            for r in sorted(stale, key=lambda r: r.index, reverse=True):
                self.runner.ipt(["-D", chain, str(r.index)])
        return changed

    def remove_base(self) -> bool:
        removed = False
        snap = self.snapshot()
        for chain in CHAINS:
            for r in sorted((r for r in snap.rules[chain] if r.base_id), key=lambda r: r.index, reverse=True):
                self.runner.ipt(["-D", chain, str(r.index)])
                removed = True
        return removed

    # -- helpers ---------------------------------------------------------

    def _move_total(self, rule: Rule, new_spec: List[str]) -> Optional[Tuple[str, str, Dict]]:
        """Before a rule is rewritten, hand its running total to the new definition
        (the kernel counter restarts at zero, the total must not).
        Returns (old key, new key, displaced entry) for a rollback."""
        if not self.counters:
            return None
        snap = self.snapshot()
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

    @staticmethod
    def _refuse_hidden(rule: Rule) -> None:
        if rule.hidden:
            raise FirewallError("Служебные правила нельзя изменять")

    @staticmethod
    def _has_twin(rules: List[Rule], n: int) -> bool:
        return n >= 2 and rules[n - 2].is_log

    @classmethod
    def _block_start(cls, rules: List[Rule], n: int) -> int:
        return n - 1 if cls._has_twin(rules, n) else n

    @staticmethod
    def _with_counters(rule: Rule) -> List[str]:
        return [*rule.spec, "-c", str(rule.pkts), str(rule.bytes)]

    @staticmethod
    def _target_index(spec: List[str]) -> int:
        try:
            return next(i for i, t in enumerate(spec) if t in ("-j", "--jump"))
        except StopIteration:
            raise FirewallError("У правила нет действия (-j)") from None

    def _twin_spec(self, twin: Rule, chain: str, action: str, on: bool) -> List[str]:
        spec = list(twin.spec)
        j = self._target_index(spec)
        del spec[j:]  # drop the target together with its own options
        if on:
            return spec + nflog_target(chain, action)
        return spec + ["-j", OFF_PREFIX + "LOG"]

    def _current(self, rule: Rule) -> List[Rule]:
        rules = self.snapshot().rules[rule.chain]
        if rule.index > len(rules) or rules[rule.index - 1].spec != rule.spec:
            raise FirewallError("Правила изменились снаружи — список обновлён, повторите действие")
        return rules

    def _insert_block(self, chain: str, pos: int, count: int, specs: List[List[str]]) -> None:
        for k, spec in enumerate(specs):
            if pos + k > count + k:
                self.runner.ipt(["-A", chain, *spec])
            else:
                self.runner.ipt(["-I", chain, str(pos + k), *spec])

    def _ensure_off_chains(self) -> None:
        existing = self.snapshot().chains
        for name in OFF_CHAINS:
            if name not in existing:
                self.runner.ipt(["-N", name])
