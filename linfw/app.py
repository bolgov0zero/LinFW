from __future__ import annotations

import asyncio
from typing import Callable, Dict, List, Optional, Tuple

from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Static, Tab, Tabs

from .chrome import StatusBar, ToolButton, TopBar, fit_title, key_label, row, sep
from .firewall import Firewall
from .model import CHAINS, FirewallError, NewRule, Rule
from .parser import Snapshot
from .lists_ui import ListsScreen
from .screens import (
    AddRuleScreen,
    ConfirmScreen,
    HelpScreen,
    JournalScreen,
    TemplateScreen,
    describe_rule,
    human_bytes,
    rule_summary,
)
from .theme import (
    ACTION_COLOR,
    ACTION_STYLE,
    AMBER,
    BLUE,
    FAINT,
    GREEN,
    LINFW_THEME,
    MUTED,
    ORANGE,
    POLICY_STYLE,
    RED,
    VIOLET,
)

COLUMNS = ("#", "Pkts", "chain", "protocol", "source", "destination", "port", "action")
REFRESH_SECONDS = 2.0
ACTIONS = ("accept", "drop", "reject")


def humanize(n: int) -> str:
    if n < 100_000_000:  # exact, with spaces between thousands: 1 532 407
        return f"{n:,}".replace(",", " ")
    value = float(n)
    for unit in ("", "K", "M", "G", "T"):
        if value < 1000:
            return f"{int(value)}" if not unit else f"{value:.1f}{unit}"
        value /= 1000
    return f"{value:.1f}P"


def row_cells(rule: Rule, pkts: Optional[int] = None) -> List[Text]:
    dim = "" if rule.enabled else "dim"
    action = rule.action + (" ●" if rule.log else "") + ("" if rule.enabled else " (off)")
    quiet = MUTED  # "any", "-" and "all" are the absence of a condition: keep them in the background
    cells = [
        Text(str(rule.number), style=MUTED, justify="right"),
        Text(humanize(rule.pkts if pkts is None else pkts), style=dim or AMBER, justify="right"),
        Text(rule.chain.lower(), style=MUTED),
        Text(rule.protocol, style=dim or (quiet if rule.protocol == "all" else "")),
        Text(rule.source or "any", style=dim or (BLUE if rule.source.startswith("@") else "" if rule.source else quiet)),
        Text(rule.destination or "any", style=dim or (BLUE if rule.destination.startswith("@") else "" if rule.destination else quiet)),
        Text((rule.port or "-") + (" +" if rule.extra else ""), style=dim or (f"bold {VIOLET}" if rule.port else quiet)),
        Text(action, style="dim" if not rule.enabled else ACTION_STYLE.get(rule.action, "bold")),
    ]
    return cells


def _bar_row(label: str, color: str, n: int, total: int, width: int) -> Text:
    """`accept   22 490 ━━━━━━━━━━━╌╌╌╌  80%`: one action's share of the packets."""
    pct = "-" if not n or not total else "<1%" if n / total < 0.01 else f"{n / total * 100:.0f}%"
    bar_w = max(width - 8 - 9 - 5 - 2, 3)
    filled = min(bar_w, max(1, round(bar_w * n / total))) if n and total else 0
    out = Text(no_wrap=True)
    out.append(label.ljust(8), style=color)
    out.append(humanize(n).rjust(9) + " ")
    out.append("━" * filled, style=color)
    out.append("╌" * (bar_w - filled), style=FAINT)
    out.append(" " + pct.rjust(4), style=color if n else MUTED)
    return out


class ChainTabs(Tabs, can_focus=False):
    pass


class RulesTable(DataTable):
    BINDINGS = [
        Binding("left", "app.prev_chain", show=False),
        Binding("right", "app.next_chain", show=False),
        Binding("enter", "app.edit", show=False),
    ]

    def on_click(self, event: events.Click) -> None:
        # double click on a data row (not the header) edits it
        if event.chain == 2 and event.style.meta.get("row", -1) >= 0:
            self.app.action_edit()


class LinFWApp(App):
    TITLE = "LinFW"
    CSS = """
    Screen { background: $background; padding: 0 1; }

    /* every screen: breadcrumb on top, key hints and the status bar at the bottom */
    #topbar { height: 2; border-bottom: solid $line-soft; }
    #crumb { width: 1fr; }
    #live { width: auto; }
    #helpbar { height: 1; align-horizontal: center; }
    #helpbar Button {
        min-width: 0; height: 1; border: none; padding: 0 1; margin: 0;
        background: transparent; color: $text;
    }
    #helpbar Button:hover { background: $pink 25%; }
    #helpbar Button:disabled { opacity: 0.3; }
    #helpbar #btn-delete:hover { background: $error 45%; }
    #helpbar .sep { width: 1; color: $faint; }
    .keyhint { width: auto; padding: 0 1; }
    #statusbar { height: 3; border: round $line; padding: 0 1; margin-top: 0; }
    #sb-left { width: 1fr; }
    #sb-name { width: auto; color: $accent; }
    #sb-right { width: 1fr; text-align: right; }
    .compact #statusbar { height: 1; border: none; background: $panel; }

    /* boxes: a thin rounded line, the focused one in pink */
    DataTable, #detail, #jstatus, #lstatus, #empty, #jbar, .panel {
        border: round $line; background: transparent;
    }
    DataTable:focus { border: round $pink; }
    DataTable { border-title-color: $text; border-title-style: bold; border-subtitle-color: $dim; border-subtitle-align: right; }
    DataTable:focus { border-title-color: $pink; }
    #rules:focus, #jtable:focus { border: round $line; border-title-color: $text; }
    DataTable, TextArea, OptionList {
        scrollbar-size-vertical: 1; scrollbar-background: $background; scrollbar-color: $faint;
        scrollbar-color-hover: $dim; scrollbar-color-active: $pink;
    }
    #detail, #jstatus, #lstatus, .panel { border-title-color: $text; border-title-style: bold; }
    DataTable > .datatable--header { background: transparent; color: $accent; text-style: bold; }
    DataTable > .datatable--odd-row { background: transparent; }
    DataTable > .datatable--even-row { background: transparent; }
    DataTable > .datatable--hover { background: $primary 10%; }
    DataTable > .datatable--cursor { background: $amber 16%; }
    DataTable:focus > .datatable--cursor { background: $amber 22%; text-style: none; }

    /* main screen */
    #chains { height: 2; background: transparent; margin-top: 0; }
    #chains Tab { padding: 0 2; color: $dim; background: transparent; }
    #chains Tab:hover { color: $text; background: $primary 10%; }
    #chains Tab.-active { color: $pink; text-style: bold; background: transparent; }
    #chains .underline--bar { color: $pink; background: $line-soft; }
    #stats { height: 7; }
    .panel { width: 1fr; height: 7; padding: 0 1; }
    #stat-packets { margin-left: 1; }
    .compact #stats { display: none; }
    #rules { height: 1fr; }
    #empty { height: 1fr; content-align: center middle; text-align: center; color: $dim; }
    #detail { height: 4; padding: 0 1; }

    /* journal and lists */
    #jbar { height: 3; padding: 0 1; border-title-color: $text; border-title-style: bold; }
    #jbar Button, #helpbar Button.jaction { min-width: 0; height: 1; border: none; padding: 0 1; margin: 0 0 0 0; background: transparent; color: $dim; }
    #jbar Button:hover { background: $primary 20%; color: $text; }
    #jbar .sep { width: 1; color: $faint; margin: 0 1; }
    #jbar Button.active { background: $accent; color: $background; text-style: bold; }
    #jbar #ja-accept.active { background: $success; }
    #jbar #ja-drop.active { background: $error; }
    #jbar #ja-reject.active { background: $warning; }
    #jtable { height: 1fr; }
    #jstatus, #lstatus { height: auto; min-height: 3; padding: 0 1; color: $text; }
    #lists-pane { height: 1fr; }
    #lists, #entries { height: 1fr; }
    #lists { width: 1fr; margin-right: 1; }
    #entries { width: 1fr; }
    TextArea { height: 8; border: round $line; background: transparent; }
    TextArea:focus { border: round $pink; }

    /* dialogs: pink frame, title and key hints cut into the border */
    ModalScreen { align: center middle; background: $background 70%; }
    .dialog {
        width: 70; max-width: 96%; height: auto; padding: 1 3;
        border: round $pink; background: $background;
        border-title-color: $pink; border-title-style: bold; border-title-align: center;
        border-subtitle-align: center;
    }
    .dialog.wide { width: 86; }
    .dialog.confirm { width: 52; }
    .question { width: 100%; text-align: center; margin-top: 1; }
    .hint { color: $dim; margin: 1 0 0 0; }
    .help-title { color: $accent; text-style: bold; margin-top: 1; }
    .help-title:first-child { margin-top: 0; }
    .row { height: 1; }
    .row.gap { margin-bottom: 1; }
    .label { width: 14; color: $dim; }
    .row Input { width: 1fr; height: 1; border: none; border-left: tall $line; padding: 0 1; background: $primary 8%; }
    .row Input:focus { border-left: tall $pink; background: $primary 22%; }
    .row Input:disabled { opacity: 0.4; }
    .row Checkbox { width: 1fr; height: 1; border: none; padding: 0; background: transparent; }
    .row Checkbox:focus { background: $primary 22%; }
    .row Button.pick { min-width: 0; width: auto; height: 1; border: none; padding: 0 1; margin-left: 1; background: transparent; color: $accent; }
    .row Button.pick:hover { background: $accent 20%; }
    #error { color: $error; height: auto; margin: 1 0 0 0; }
    .buttons { height: 3; align-horizontal: center; margin-top: 1; }
    .buttons Button {
        min-width: 12; height: 3; padding: 0 2; margin: 0 2;
        border: round $line; background: transparent; color: $dim; text-style: none;
    }
    .buttons Button:hover { color: $text; border: round $faint; background: transparent; }
    .buttons Button:focus { color: $pink; border: round $pink; background: transparent; text-style: bold; }
    .buttons Button.danger { color: $error; }
    .buttons Button.danger:focus { color: $error; }
    .dialog OptionList { height: auto; max-height: 10; border: round $line; background: transparent; padding: 0 1; }
    .dialog OptionList:focus { border: round $pink; }
    .dialog OptionList > .option-list--option-highlighted { background: $amber 16%; text-style: none; }
    .dialog OptionList:focus > .option-list--option-highlighted { background: $amber 22%; text-style: none; }
    """

    BINDINGS = [
        Binding("f1,a", "add", "Добавить"),
        Binding("e", "edit", "Изменить"),
        Binding("f2,delete,x", "delete", "Удалить"),
        Binding("f3,t", "template", "Шаблон"),
        Binding("f4,u", "move(-1)", "Вверх"),
        Binding("f5,d", "move(1)", "Вниз"),
        Binding("f6,space", "toggle", "Выключить"),
        Binding("f7,j", "journal", "Журнал"),
        Binding("f8,l", "lists", "Списки"),
        Binding("question_mark", "help", "Ещё"),
        Binding("r", "refresh_now", "Обновить"),
        Binding("f10,q,ctrl+q", "quit", "Выход"),
        Binding("escape", "leave", "Выход"),
        Binding("left", "prev_chain", show=False),
        Binding("right", "next_chain", show=False),
    ]

    def __init__(self, firewall: Firewall) -> None:
        super().__init__()
        # registered before the first screen is built: the CSS below uses the theme's own variables ($pink, $line ...)
        self.register_theme(LINFW_THEME)
        self.theme = LINFW_THEME.name
        self.fw = firewall
        self.snapshot = Snapshot()
        self.current = CHAINS[0]
        # None = the table no longer matches what was drawn last (e.g. after a tab switch): redraw
        self._shown: Optional[List[Rule]] = None
        self._select: Optional[Tuple[str, int]] = None
        self._lock = asyncio.Lock()
        self._persist_note = Text()
        self._base_failed = False
        self._totals: Dict[str, Tuple[int, int]] = {}  # running totals that survive counter resets
        self._lists_info: Tuple[Dict[str, int], Optional[str]] = ({}, None)  # (name -> size, why unavailable)

    # -- layout ----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield TopBar("iptables", self.current)
        yield ChainTabs(*[Tab(name, id=f"tab-{name}") for name in CHAINS], id="chains")
        with Horizontal(id="stats"):
            left, right = Static("", id="stat-chain", classes="panel"), Static("", id="stat-packets", classes="panel")
            left.border_title = "Цепочка"
            right.border_title = "Пакеты"
            yield left
            yield right
        # "renderable": the green/red/orange action text stays coloured under the cursor
        table = RulesTable(id="rules", cursor_type="row")
        table.cursor_foreground_priority = "renderable"
        yield table
        empty = Static("", id="empty")
        empty.display = False
        yield empty
        detail = Static("", id="detail")
        detail.border_title = "Правило"
        yield detail
        with Horizontal(id="helpbar"):
            yield ToolButton(key_label("F1", "добавить"), id="btn-add")
            yield sep()
            yield ToolButton(key_label("F2", "удалить"), id="btn-delete")
            yield sep()
            yield ToolButton(key_label("F3", "шаблон"), id="btn-template")
            yield sep()
            yield ToolButton(key_label("F4", "▲"), id="btn-up")
            yield sep()
            yield ToolButton(key_label("F5", "▼"), id="btn-down")
            yield sep()
            yield ToolButton(key_label("F6", "выкл"), id="btn-toggle")
            yield sep()
            yield ToolButton(key_label("F7", "журнал"), id="btn-journal")
            yield sep()
            yield ToolButton(key_label("F8", "списки"), id="btn-lists")
            yield sep()
            yield ToolButton(key_label("F10", "выход"), id="btn-quit")
        yield StatusBar("Правила")

    def on_mount(self) -> None:
        table = self.table
        for name in COLUMNS:
            table.add_column(name, key=name)
        table.focus()
        info = self.fw.persist_info()
        self._persist_note = (
            Text.assemble(("● ", GREEN), ("автосохранение: ", MUTED), info)
            if info
            else Text.assemble(("● ", ORANGE), ("автосохранение не настроено", ORANGE))
        )
        self.set_interval(REFRESH_SECONDS, self.action_refresh_now)
        self.run_worker(self._refresh())

    def on_resize(self, event: events.Resize) -> None:
        # a short terminal gives its rows to the table: the meter and the panels step aside
        self.set_class(event.size.height < 32, "compact")
        self.call_after_refresh(self._update_stats)

    def _main(self):
        """The screen that hosts the rules table (the journal may be on top of it)."""
        return self.screen_stack[0]

    @property
    def table(self) -> RulesTable:
        return self._main().query_one("#rules", RulesTable)

    # -- data ------------------------------------------------------------

    async def action_refresh_now(self) -> None:
        if len(self.screen_stack) == 1:
            await self._refresh()

    async def _refresh(self) -> None:
        if self._lock.locked():
            return
        async with self._lock:
            try:
                await self._load_snapshot()
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
        await self._load_snapshot()
        self.notify("Базовые правила (loopback, established/related) применены")

    def _pkts(self, rule: Rule) -> int:
        return self._totals.get(rule.key, (rule.pkts, rule.bytes))[0]

    async def _load_snapshot(self) -> None:
        self.snapshot = await asyncio.to_thread(self.fw.snapshot)
        self._totals = await asyncio.to_thread(self.fw.counter_totals, self.snapshot)
        self._lists_info = await asyncio.to_thread(self.fw.lists_overview)

    def _visible(self) -> List[Rule]:
        return [r for r in self.snapshot.rules.get(self.current, []) if not r.hidden]

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
                for col, cell in zip(COLUMNS, row_cells(rule, self._pkts(rule))):
                    table.update_cell(rule.key, col, cell, update_width=True)
        else:
            cursor_key = self._selected_key()
            scroll = table.scroll_y
            table.clear()
            for rule in rules:
                table.add_row(*row_cells(rule, self._pkts(rule)), key=rule.key)
            target = cursor_key
            if wanted:
                # wanted = (chain, visible number); if that rule is gone, take its closest neighbour
                same = [r for r in rules if r.chain == wanted[0]]
                if same:
                    target = min(same, key=lambda r: abs(r.number - wanted[1])).key
            if target in new_keys:
                table.move_cursor(row=new_keys.index(target), animate=False)
            table.scroll_y = scroll
        self._shown = rules
        self._show_empty(not rules)
        self._update_tabs()
        self._update_detail()
        self._update_stats()
        self._update_status()

    def _selected_rule(self) -> Optional[Rule]:
        table = self.table
        if not self._shown or not 0 <= table.cursor_row < len(self._shown):
            return None
        return self._shown[table.cursor_row]

    def _selected_key(self) -> Optional[str]:
        rule = self._selected_rule()
        return rule.key if rule else None

    def _show_empty(self, empty: bool) -> None:
        """A chain without rules shows a hint instead of a bare table header."""
        main = self._main()
        table, hint = self.table, main.query_one("#empty", Static)
        if hint.display == empty:
            return
        table.display = not empty
        hint.display = empty
        if empty:
            policy = self.snapshot.policies.get(self.current, "?")
            colour = POLICY_STYLE.get(policy, "")
            hint.update(
                Text.assemble(
                    (f"В цепочке {self.current} нет своих правил\n", "bold"),
                    ("Политика по умолчанию: ", ""),
                    (policy, f"bold {colour}"),
                    "\n\n",
                    ("F1", "bold"), " добавить правило   ·   ", ("F3", "bold"), " выбрать шаблон",
                )
            )
        else:
            table.focus()

    def _update_tabs(self) -> None:
        """INPUT  6  ACCEPT: how many rules a chain has and what its default policy is."""
        for chain in CHAINS:
            tab = self._main().query_one(f"#tab-{chain}", Tab)
            count = sum(1 for r in self.snapshot.rules.get(chain, []) if not r.hidden)
            policy = self.snapshot.policies.get(chain, "?")
            tab.label = Text.assemble(
                chain, "  ", (str(count), "bold"), "  ", (policy.lower(), POLICY_STYLE.get(policy, "dim"))
            )

    def _sync_toolbar(self, rule: Optional[Rule]) -> None:
        """Buttons that cannot do anything right now are dimmed; the toggle says what it will do."""
        main, row, total = self._main(), self.table.cursor_row, len(self._shown or [])
        main.query_one("#btn-delete", Button).disabled = rule is None
        main.query_one("#btn-toggle", Button).disabled = rule is None
        main.query_one("#btn-up", Button).disabled = rule is None or row <= 0
        main.query_one("#btn-down", Button).disabled = rule is None or row >= total - 1
        verb = "вкл" if rule is not None and not rule.enabled else "выкл"
        main.query_one("#btn-toggle", Button).label = key_label("F6", verb)

    def _update_detail(self) -> None:
        rule = self._selected_rule()
        self._sync_toolbar(rule)
        detail = Text(no_wrap=True, overflow="ellipsis")
        box = self._main().query_one("#detail", Static)
        box.border_title = f"Правило #{rule.number}" if rule else "Правило"
        total = len(self._shown or [])
        self.table.border_subtitle = f"Правило {self.table.cursor_row + 1} из {total}" if rule else ""
        if rule:
            pkts, nbytes = self._totals.get(rule.key, (rule.pkts, rule.bytes))
            detail = describe_rule(rule, pkts, nbytes)
            detail.no_wrap, detail.overflow = True, "ellipsis"
            detail.append("\n" + rule.describe(), style="dim")
        box.update(detail)

    def _update_status(self) -> None:
        main = self._main()
        main.query_one(TopBar).set_trail("iptables", self.current)
        main.query_one(TopBar).set_status(self._persist_note)
        total = sum(1 for rules in self.snapshot.rules.values() for r in rules if not r.hidden)
        main.query_one(StatusBar).set_right(f"правил: {total} · списков: {len(self._lists_info[0])}")

    def _update_stats(self) -> None:
        """The two panels: what this chain has and how its packets split between the actions."""
        main = self._main()
        rules = self._visible()
        packets = {a: 0 for a in ACTIONS}
        nbytes = 0
        for r in rules:
            if r.enabled and r.action in packets:
                packets[r.action] += self._pkts(r)
            nbytes += self._totals.get(r.key, (r.pkts, r.bytes))[1]
        total = sum(packets.values())
        on = sum(1 for r in rules if r.enabled)
        chain_panel, packets_panel = main.query_one("#stat-chain", Static), main.query_one("#stat-packets", Static)
        width = chain_panel.content_size.width
        if width < 12:
            return
        policy = self.snapshot.policies.get(self.current, "?")
        value = lambda n: Text(str(n), style="bold")  # noqa: E731
        chain_panel.update(
            Text("\n").join(
                [
                    row(Text("правил", style=AMBER), value(len(rules)), width),
                    row(Text("включено", style=BLUE), value(on), width),
                    row(Text("выключено", style=VIOLET), value(len(rules) - on), width),
                    row(Text("журнал ●", style=GREEN), value(sum(1 for r in rules if r.log)), width),
                    row(Text("политика", style=MUTED), Text(policy.lower(), style=f"bold {POLICY_STYLE.get(policy, MUTED)}"), width),
                ]
            )
        )
        width = packets_panel.content_size.width
        lines = [_bar_row(a, ACTION_COLOR[a], packets[a], total, width) for a in ACTIONS]
        lines.append(row(Text("выкл.", style=MUTED), Text(f"{len(rules) - on} прав." if len(rules) - on else "-", style=MUTED), width))
        lines.append(row(Text("всего", style=MUTED), Text.assemble((humanize(total), "bold"), ("  " + human_bytes(nbytes), MUTED)), width))
        packets_panel.update(Text("\n").join(lines))
        packets_panel.border_title = fit_title(
            Text("Пакеты"), Text(f"{humanize(packets['drop'] + packets['reject'])} отклонено", style=f"bold {RED}"), packets_panel.size.width
        )

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self) -> None:
        self._update_detail()

    # -- chains ----------------------------------------------------------

    @on(Tabs.TabActivated)
    def _tab_activated(self, event: Tabs.TabActivated) -> None:
        name = (event.tab.id or f"tab-{CHAINS[0]}")[4:]
        if name != self.current:
            self.current = name
            self._shown = None
            self._render()
        self.table.focus()

    def action_next_chain(self) -> None:
        self._main().query_one(ChainTabs).action_next_tab()

    def action_prev_chain(self) -> None:
        self._main().query_one(ChainTabs).action_previous_tab()

    # -- actions ---------------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        # the toolbar shortcuts must not fire while a dialog is open
        if action not in ("quit",) and len(self.screen_stack) > 1:
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
                await self._load_snapshot()
            except FirewallError as exc:
                self.notify(str(exc), severity="error", timeout=8)
        self._render()
        return ok

    @on(Button.Pressed, "#btn-add")
    def action_add(self) -> None:

        def done(rule: Optional[NewRule]) -> None:
            if rule:
                self.run_worker(self._add(rule, "Правило добавлено"))

        self.push_screen(AddRuleScreen(self.current, None, *self._lists_info), done)

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

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
            if rule.spec == spec:
                self._select = (rule.chain, rule.number)
                self._shown = None
                self._render()
                return

    def action_edit(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        if not rule.editable:
            self.notify(
                "У правила есть условия, которых нет в окне редактирования (см. «+» в колонке port). "
                "Удалите его и создайте заново.",
                severity="warning",
                timeout=8,
            )
            return

        def done(new: Optional[NewRule]) -> None:
            if new:
                self.run_worker(self._edit(rule, new))

        self.push_screen(AddRuleScreen(rule.chain, rule, *self._lists_info), done)

    async def _edit(self, rule: Rule, new: NewRule) -> None:
        if await self._apply("Правило изменено", lambda: self.fw.edit(rule, new)):
            self._select = (rule.chain, rule.number)
            self._shown = None
            self._render()

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
        if await self._apply("Правило удалено", lambda: self.fw.delete(rule)):
            self._select = (rule.chain, max(rule.number - 1, 1))
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
            self._select = (rule.chain, rule.number + delta)
            self._shown = None
            self._render()

    @on(Button.Pressed, "#btn-quit")
    def _btn_quit(self) -> None:
        self.exit()

    def action_leave(self) -> None:
        """Esc on the main screen quits. Dialogs and the journal bind Esc themselves
        (it closes them), and check_action keeps this one inert while they are open."""
        self.exit()

    @on(Button.Pressed, "#btn-journal")
    def action_journal(self) -> None:
        self.push_screen(JournalScreen(self.fw))

    @on(Button.Pressed, "#btn-lists")
    def action_lists(self) -> None:
        # the rule dialogs read the lists from a cache: refresh it when the lists window closes
        self.push_screen(ListsScreen(self.fw), lambda _: self.run_worker(self._refresh()))

    @on(Button.Pressed, "#btn-toggle")
    def action_toggle(self) -> None:
        rule = self._selected_rule()
        if rule:
            verb = "выключено" if rule.enabled else "включено"
            self.run_worker(self._toggle(rule, f"Правило {verb}"))

    async def _toggle(self, rule: Rule, message: str) -> None:
        await self._apply(message, lambda: self.fw.toggle(rule))
