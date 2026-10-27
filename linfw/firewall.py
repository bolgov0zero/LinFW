from __future__ import annotations

import subprocess
from typing import List, Optional

from . import persist
from .model import ACTIONS, OFF_CHAINS, OFF_PREFIX, FirewallError, NewRule, Rule
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
        rules = self.snapshot().rules[new.chain]
        pos = len(rules) + 1
        # a rule appended after a catch-all DROP/REJECT would never match
        if not new.is_catch_all_deny:
            for r in rules:
                if r.is_catch_all_deny:
                    pos = r.index
                    break
        self._insert(new.chain, pos, len(rules), new.to_spec())

    def delete(self, rule: Rule) -> None:
        self._current(rule)
        self.runner.ipt(["-D", rule.chain, str(rule.index)])

    def move(self, rule: Rule, delta: int) -> bool:
        """Move a rule one step up (-1) or down (+1). The copy is inserted
        before the original is removed, so there is never a gap in the chain."""
        rules = self._current(rule)
        n = rule.index
        counters = ["-c", str(rule.pkts), str(rule.bytes)]
        if delta < 0:
            if n == 1:
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

    # -- helpers ---------------------------------------------------------

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
