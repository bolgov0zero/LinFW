from __future__ import annotations

import subprocess
from typing import List, Optional

from . import persist
from .model import ACTIONS, CHAINS, OFF_CHAINS, OFF_PREFIX, FirewallError, NewRule, Rule, base_ids, base_specs
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


class Firewall:
    """Rule operations. Every mutation re-reads the chain first and refuses to
    act if the rule is no longer where the UI last saw it."""

    def __init__(self, runner) -> None:
        self.runner = runner

    def snapshot(self) -> Snapshot:
        return parse_save(self.runner.save_text())

    def persist(self) -> str:
        return self.runner.persist()

    def persist_info(self) -> Optional[str]:
        return self.runner.persist_info()

    def add(self, new: NewRule) -> None:
        new = new.validated()
        self.runner.ipt(["-A", new.chain, *new.to_spec()])

    def edit(self, rule: Rule, new: NewRule) -> None:
        """Replace a rule in place (same chain, same position, same on/off state).
        Counters start from zero since it is, in effect, a different rule."""
        self._current(rule)
        self._refuse_base(rule)
        new = new.validated()
        if new.chain != rule.chain:
            raise FirewallError("Цепочку существующего правила изменить нельзя")
        spec = new.to_spec()
        if not rule.enabled:
            self._ensure_off_chains()
            spec[-1] = OFF_PREFIX + new.action
        self.runner.ipt(["-R", rule.chain, str(rule.index), *spec])

    def delete(self, rule: Rule) -> None:
        self._current(rule)
        self._refuse_base(rule)
        self.runner.ipt(["-D", rule.chain, str(rule.index)])

    def move(self, rule: Rule, delta: int) -> bool:
        """Move a rule one step up (-1) or down (+1). The copy is inserted
        before the original is removed, so there is never a gap in the chain."""
        rules = self._current(rule)
        self._refuse_base(rule)
        n = rule.index
        counters = ["-c", str(rule.pkts), str(rule.bytes)]
        if delta < 0:
            # never move a rule above the base rules at the top of the chain
            if n == 1 or rules[n - 2].hidden:
                return False
            self._insert(rule.chain, n - 1, len(rules), [*rule.spec, *counters])
            self.runner.ipt(["-D", rule.chain, str(n + 1)])
        else:
            if n == len(rules):
                return False
            self._insert(rule.chain, n + 2, len(rules), [*rule.spec, *counters])
            self.runner.ipt(["-D", rule.chain, str(n)])
        return True

    def toggle(self, rule: Rule) -> bool:
        """Enable/disable a rule in place. Returns the new enabled state."""
        self._current(rule)
        self._refuse_base(rule)
        action = rule.action.upper()
        if action not in ACTIONS:
            raise FirewallError(f"Правило с действием {action} нельзя выключить")
        spec = list(rule.spec)
        try:
            j = next(i for i, t in enumerate(spec) if t in ("-j", "--jump"))
        except StopIteration:
            raise FirewallError("У правила нет действия (-j)") from None
        if rule.enabled:
            self._ensure_off_chains()
            spec[j + 1] = OFF_PREFIX + action
            # --reject-with is only valid together with the REJECT target
            while "--reject-with" in spec:
                k = spec.index("--reject-with")
                del spec[k:k + 2]
        else:
            spec[j + 1] = action
        self.runner.ipt(["-R", rule.chain, str(rule.index), *spec, "-c", str(rule.pkts), str(rule.bytes)])
        return not rule.enabled

    # -- base rules ------------------------------------------------------

    @staticmethod
    def _chain_base_ok(chain: str, rules: List[Rule]) -> bool:
        want = base_ids(chain)
        return [r.base_id for r in rules[: len(want)]] == want and not any(
            r.hidden for r in rules[len(want):]
        )

    def base_ok(self, snap: Snapshot) -> bool:
        return all(self._chain_base_ok(c, snap.rules[c]) for c in CHAINS)

    def ensure_base(self) -> bool:
        """Put the base rules (loopback, established/related) at the top of every
        chain. Returns True if anything had to be changed. New copies go in
        before stale ones are removed, so traffic is never left unprotected."""
        snap = self.snapshot()
        changed = False
        for chain in CHAINS:
            if self._chain_base_ok(chain, snap.rules[chain]):
                continue
            changed = True
            specs = base_specs(chain)
            for pos, spec in enumerate(specs, start=1):
                self.runner.ipt(["-I", chain, str(pos), *spec])
            stale = [r for r in self.snapshot().rules[chain] if r.hidden and r.index > len(specs)]
            for r in sorted(stale, key=lambda r: r.index, reverse=True):
                self.runner.ipt(["-D", chain, str(r.index)])
        return changed

    def remove_base(self) -> bool:
        removed = False
        snap = self.snapshot()
        for chain in CHAINS:
            for r in sorted((r for r in snap.rules[chain] if r.hidden), key=lambda r: r.index, reverse=True):
                self.runner.ipt(["-D", chain, str(r.index)])
                removed = True
        return removed

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _refuse_base(rule: Rule) -> None:
        if rule.hidden:
            raise FirewallError("Базовые правила нельзя изменять")

    def _current(self, rule: Rule) -> List[Rule]:
        rules = self.snapshot().rules[rule.chain]
        if rule.index > len(rules) or rules[rule.index - 1].spec != rule.spec:
            raise FirewallError("Правила изменились снаружи — список обновлён, повторите действие")
        return rules

    def _insert(self, chain: str, pos: int, count: int, spec: List[str]) -> None:
        if pos > count:
            self.runner.ipt(["-A", chain, *spec])
        else:
            self.runner.ipt(["-I", chain, str(pos), *spec])

    def _ensure_off_chains(self) -> None:
        existing = self.snapshot().chains
        for name in OFF_CHAINS:
            if name not in existing:
                self.runner.ipt(["-N", name])
