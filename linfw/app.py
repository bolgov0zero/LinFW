from __future__ import annotations

import asyncio
from typing import Callable, Dict, List, Optional, Tuple

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static, Tab, Tabs

from . import __version__
from .firewall import Firewall
from .model import CHAINS, FirewallError, NewRule, Rule
from .parser import Snapshot
from .screens import AddRuleScreen, ConfirmScreen, TemplateScreen, rule_summary

TABS = ("ALL",) + CHAINS
ACTION_STYLE = {"accept": "bold #2ecc71", "drop": "bold #ff5555", "reject": "bold #ff9f1a"}
POLICY_STYLE = {"ACCEPT": "#2ecc71", "DROP": "#ff5555", "REJECT": "#ff9f1a"}
COLUMNS = ("#", "Pkts", "chain", "protocol", "source", "destination", "port", "action")
REFRESH_SECONDS = 2.0


def humanize(n: int) -> str:
    value = float(n)
    for unit in ("", "K", "M", "G", "T"):
        if value < 1000:
            return f"{int(value)}" if not unit else f"{value:.1f}{unit}"
        value /= 1000
    return f"{value:.1f}P"


def row_cells(rule: Rule) -> List[Text]:
    dim = "" if rule.enabled else "dim"
    action = rule.action if rule.enabled else f"{rule.action} (off)"
    cells = [
        Text(str(rule.number), style=dim, justify="right"),
        Text(humanize(rule.pkts), style=dim, justify="right"),
        Text(rule.chain.lower(), style=dim),
        Text(rule.protocol, style=dim),
        Text(rule.source or "any", style=dim),
        Text(rule.destination or "any", style=dim),
        Text((rule.port or "-") + (" +" if rule.extra else ""), style=dim),
        Text(action, style="dim" if not rule.enabled else ACTION_STYLE.get(rule.action, "bold")),
    ]
    return cells


class ToolButton(Button, can_focus=False):
    """Toolbar buttons never steal focus, so the arrow keys keep driving the table."""


class ChainTabs(Tabs, can_focus=False):
    pass


class RulesTable(DataTable):
    BINDINGS = [
        Binding("left", "app.prev_chain", show=False),
        Binding("right", "app.next_chain", show=False),
    ]


class LinFWApp(App):
    TITLE = "LinFW"
    CSS = """
    Screen { background: $surface; }
    #toolbar { height: 1; padding: 0 1; background: $panel; }
    #toolbar Button { min-width: 0; height: 1; border: none; padding: 0 2; margin-right: 1; }
    #toolbar .spacer { width: 1fr; }
    #brand { width: auto; height: 1; color: $accent; text-style: bold; }
    #chains { height: 2; }
    #rules { height: 1fr; }
    DataTable { background: $surface; }
    DataTable > .datatable--cursor { background: $primary 35%; }
    DataTable:focus > .datatable--cursor { background: $primary 45%; }
    #detail { height: 1; padding: 0 1; color: $text-muted; background: $panel; }
    #status { height: 1; padding: 0 1; background: $panel-darken-1; }

    ModalScreen { align: center middle; }
    .dialog {
        width: 72; max-width: 96%; height: auto; padding: 1 2;
        border: thick $accent; background: $panel;
    }
    .title { text-style: bold; width: 100%; content-align: center middle; margin-bottom: 1; }
    .hint { color: $text-muted; margin: 1 0; }
    .row { height: auto; margin-bottom: 1; }
    .label { width: 14; }
    .row Input { width: 1fr; height: 1; border: none; padding: 0 1; background: $boost; }
    .row Input:focus { background: $primary 40%; }
    .row Input:disabled { opacity: 0.4; }
    .row RadioSet { layout: horizontal; width: 1fr; height: auto; border: none; padding: 0; background: transparent; }
    .row RadioButton { width: auto; padding: 0 2 0 0; background: transparent; }
    #error { color: $error; height: auto; margin-bottom: 1; }
    .buttons { height: 1; align-horizontal: center; }
    .buttons Button { min-width: 0; height: 1; border: none; padding: 0 2; margin: 0 1; }
    .dialog OptionList { height: auto; max-height: 10; border: tall $primary; }
    """

    BINDINGS = [
        Binding("f1,a", "add", "Добавить"),
        Binding("f2,delete,x", "delete", "Удалить"),
        Binding("f3,t", "template", "Шаблон"),
        Binding("f4,u", "move(-1)", "Вверх"),
        Binding("f5,d", "move(1)", "Вниз"),
        Binding("f6,space", "toggle", "Выключить"),
        Binding("r", "refresh_now", "Обновить"),
        Binding("q,ctrl+q", "quit", "Выход"),
    ]

    def __init__(self, firewall: Firewall) -> None:
        super().__init__()
        self.fw = firewall
        self.snapshot = Snapshot()
        self.current = "ALL"
        # None = the table no longer matches what was drawn last (e.g. after a tab switch): redraw
        self._shown: Optional[List[Rule]] = None
        self._select: Optional[Tuple[str, int]] = None
        self._lock = asyncio.Lock()
        self._persist_note = ""
        self._base_failed = False

    # -- layout ----------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="toolbar"):
            yield ToolButton("F1 Добавить", id="btn-add", variant="success")
            yield ToolButton("F2 Удалить", id="btn-delete", variant="error")
            yield ToolButton("F3 Шаблон", id="btn-template", variant="primary")
            yield ToolButton("F4 ▲ Вверх", id="btn-up")
            yield ToolButton("F5 ▼ Вниз", id="btn-down")
            yield ToolButton("F6 Выкл/Вкл", id="btn-toggle", variant="warning")
            yield Static("", classes="spacer")
            yield Static(f"LinFW {__version__}", id="brand")
        yield ChainTabs(*[Tab(name, id=f"tab-{name}") for name in TABS], id="chains")
        # "renderable": the green/red/orange action text stays coloured under the cursor
        table = RulesTable(id="rules", cursor_type="row", zebra_stripes=True)
        table.cursor_foreground_priority = "renderable"
        yield table
        yield Static("", id="detail")
        yield Static("", id="status")

    def on_mount(self) -> None:
        table = self.table
        for name in COLUMNS:
            table.add_column(name, key=name)
        table.focus()
        info = self.fw.persist_info()
        self._persist_note = (
            f"автосохранение: {info}" if info else "[b #ff9f1a]автосохранение не настроено[/]"
        )
        self.set_interval(REFRESH_SECONDS, self.action_refresh_now)
        self.run_worker(self._refresh())

    @property
    def table(self) -> RulesTable:
        return self.query_one("#rules", RulesTable)

    # -- data ------------------------------------------------------------

    async def action_refresh_now(self) -> None:
        if not isinstance(self.screen, ModalScreen):
            await self._refresh()

    async def _refresh(self) -> None:
        if self._lock.locked():
            return
        async with self._lock:
            try:
                self.snapshot = await asyncio.to_thread(self.fw.snapshot)
            except FirewallError as exc:
                self.notify(str(exc), severity="error", timeout=8)
                return
            await self._ensure_base()
        self._render()

    async def _ensure_base(self) -> None:
        """Restore the hidden base rules if they are missing or not on top.
        Called with the lock held. After one failure it stops retrying."""
        if self._base_failed or self.fw.base_ok(self.snapshot):
            return
        try:
            await asyncio.to_thread(self.fw.ensure_base)
        except FirewallError as exc:
            self._base_failed = True
            self.notify(f"Базовые правила не применены: {exc}", severity="error", timeout=10)
            return
        try:
            await asyncio.to_thread(self.fw.persist)
        except FirewallError as exc:
            self.notify(str(exc), severity="warning", timeout=8)
        self.snapshot = await asyncio.to_thread(self.fw.snapshot)
        self.notify("Базовые правила (loopback, established/related) применены")

    def _visible(self) -> List[Rule]:
        chains = CHAINS if self.current == "ALL" else (self.current,)
        return [r for c in chains for r in self.snapshot.rules.get(c, []) if not r.hidden]

    def _render(self) -> None:
        table = self.table
        rules = self._visible()
        old_keys = [r.key for r in self._shown or []]
        new_keys = [r.key for r in rules]
        same_layout = self._shown is not None and old_keys == new_keys and all(
            a.spec == b.spec and a.enabled == b.enabled for a, b in zip(self._shown, rules)
        )
        wanted = self._select
        self._select = None
        if same_layout:
            # only counters moved: update cells in place, cursor and scroll stay put
            for rule in rules:
                for col, cell in zip(COLUMNS, row_cells(rule)):
                    table.update_cell(rule.key, col, cell, update_width=True)
        else:
            cursor_key = self._selected_key()
            scroll = table.scroll_y
            table.clear()
            for rule in rules:
                table.add_row(*row_cells(rule), key=rule.key)
            target = f"{wanted[0]}:{wanted[1]}" if wanted else cursor_key
            if wanted and target not in new_keys:
                # the wanted rule is gone (deleted): land on its closest neighbour
                same = [r for r in rules if r.chain == wanted[0]]
                if same:
                    target = min(same, key=lambda r: abs(r.index - wanted[1])).key
            if target in new_keys:
                table.move_cursor(row=new_keys.index(target), animate=False)
            table.scroll_y = scroll
        self._shown = rules
        self._update_detail()
        self._update_status()

    def _selected_rule(self) -> Optional[Rule]:
        table = self.table
        if not self._shown or not 0 <= table.cursor_row < len(self._shown):
            return None
        return self._shown[table.cursor_row]

    def _selected_key(self) -> Optional[str]:
        rule = self._selected_rule()
        return rule.key if rule else None

    def _update_detail(self) -> None:
        rule = self._selected_rule()
        self.query_one("#detail", Static).update(
            Text(rule.describe() if rule else "Правил нет — нажмите F1 или F3", overflow="ellipsis", no_wrap=True)
        )

    def _update_status(self) -> None:
        policies = "  ".join(
            f"{c}: [{POLICY_STYLE.get(self.snapshot.policies.get(c, ''), 'dim')}]"
            f"{self.snapshot.policies.get(c, '?')}[/]"
            for c in CHAINS
        )
        self.query_one("#status", Static).update(
            f"Policy  {policies}   ·   {self._persist_note}   ·   базовые правила: lo, established   ·   q выход"
        )

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self) -> None:
        self._update_detail()

    # -- chains ----------------------------------------------------------

    @on(Tabs.TabActivated)
    def _tab_activated(self, event: Tabs.TabActivated) -> None:
        name = (event.tab.id or "tab-ALL")[4:]
        if name != self.current:
            self.current = name
            self._shown = None
            self._render()
        self.table.focus()

    def action_next_chain(self) -> None:
        self.query_one(ChainTabs).action_next_tab()

    def action_prev_chain(self) -> None:
        self.query_one(ChainTabs).action_previous_tab()

    # -- actions ---------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        # the toolbar shortcuts must not fire while a dialog is open
        if action not in ("quit",) and isinstance(self.screen, ModalScreen):
            return False
        return True

    async def _apply(self, done: str, op: Callable[[], object]) -> bool:
        """Run a firewall change off the UI thread, persist it, refresh the table."""
        async with self._lock:
            try:
                await asyncio.to_thread(op)
                saved = await asyncio.to_thread(self.fw.persist)
            except FirewallError as exc:
                self.notify(str(exc), severity="error", timeout=8)
                ok = False
            else:
                self.notify(f"{done} · сохранено ({saved})")
                ok = True
            try:
                self.snapshot = await asyncio.to_thread(self.fw.snapshot)
            except FirewallError as exc:
                self.notify(str(exc), severity="error", timeout=8)
        self._render()
        return ok

    @on(Button.Pressed, "#btn-add")
    def action_add(self) -> None:
        chain = self.current if self.current in CHAINS else "INPUT"

        def done(rule: Optional[NewRule]) -> None:
            if rule:
                self.run_worker(self._add(rule, "Правило добавлено"))

        self.push_screen(AddRuleScreen(chain), done)

    @on(Button.Pressed, "#btn-template")
    def action_template(self) -> None:
        def done(rule: Optional[NewRule]) -> None:
            if rule:
                self.run_worker(self._add(rule, "Шаблон применён"))

        self.push_screen(TemplateScreen(), done)

    async def _add(self, rule: NewRule, message: str) -> None:
        if await self._apply(message, lambda: self.fw.add(rule)):
            self._select_last(rule)

    def _select_last(self, new: NewRule) -> None:
        """Put the cursor on the rule that was just added (best effort)."""
        spec = tuple(new.to_spec())
        for rule in self.snapshot.rules.get(new.chain, []):
            if rule.spec == spec or rule.spec[: len(spec)] == spec:
                self._select = (rule.chain, rule.index)
                self._shown = None
                self._render()
                return

    @on(Button.Pressed, "#btn-delete")
    def action_delete(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return

        def done(confirmed: Optional[bool]) -> None:
            if confirmed:
                self.run_worker(self._delete(rule))

        self.push_screen(ConfirmScreen(rule_summary(rule)), done)

    async def _delete(self, rule: Rule) -> None:
        index = max(rule.index - 1, 1)
        if await self._apply("Правило удалено", lambda: self.fw.delete(rule)):
            self._select = (rule.chain, index)
            self._shown = None
            self._render()

    @on(Button.Pressed, "#btn-up")
    def _btn_up(self) -> None:
        self.action_move(-1)

    @on(Button.Pressed, "#btn-down")
    def _btn_down(self) -> None:
        self.action_move(1)

    def action_move(self, delta: int) -> None:
        rule = self._selected_rule()
        if rule:
            self.run_worker(self._move(rule, delta))

    async def _move(self, rule: Rule, delta: int) -> None:
        moved = []

        def op() -> None:
            moved.append(self.fw.move(rule, delta))

        if await self._apply("Правило перемещено", op) and moved and moved[0]:
            self._select = (rule.chain, rule.index + delta)
            self._shown = None
            self._render()

    @on(Button.Pressed, "#btn-toggle")
    def action_toggle(self) -> None:
        rule = self._selected_rule()
        if rule:
            verb = "выключено" if rule.enabled else "включено"
            self.run_worker(self._toggle(rule, f"Правило {verb}"))

    async def _toggle(self, rule: Rule, message: str) -> None:
        await self._apply(message, lambda: self.fw.toggle(rule))
