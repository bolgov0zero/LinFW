from __future__ import annotations

import asyncio
from typing import List, Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, OptionList, RadioButton, RadioSet, Static
from textual.widgets.option_list import Option

from .journal import MAX_ENTRIES, RETENTION_DAYS, LogEntry
from .model import ACTIONS, CHAINS, PROTOCOLS, FirewallError, NewRule, Rule

ACTION_STYLE = {"accept": "bold #2ecc71", "drop": "bold #ff5555", "reject": "bold #ff9f1a"}


class ToolButton(Button, can_focus=False):
    """Toolbar buttons never steal focus, so the arrow keys keep driving the table."""

TEMPLATES = [
    ("Открыть для всех SSH (порт 22)", NewRule("INPUT", "tcp", "ACCEPT", port="22")),
    ("Открыть для всех ICMP", NewRule("INPUT", "icmp", "ACCEPT")),
    ("Открыть для всех HTTP/HTTPS (порты 80, 443)", NewRule("INPUT", "tcp", "ACCEPT", port="80,443")),
]


def _choice(label: str, name: str, values: List[str], selected: str, disabled: bool = False) -> ComposeResult:
    with Horizontal(classes="row"):
        yield Label(label, classes="label")
        with RadioSet(id=name, disabled=disabled):
            for v in values:
                yield RadioButton(v.lower() if name == "action" else v, value=(v == selected), name=v)


def _picked(dialog: ModalScreen, name: str) -> str:
    button = dialog.query_one(f"#{name}", RadioSet).pressed_button
    return button.name if button and button.name else ""


class AddRuleScreen(ModalScreen[Optional[NewRule]]):
    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def __init__(self, chain: str = "INPUT", rule: Optional[Rule] = None) -> None:
        super().__init__()
        self._rule = rule  # set when editing an existing rule
        self._initial = rule.to_new() if rule else NewRule(chain if chain in CHAINS else "INPUT")

    def compose(self) -> ComposeResult:
        init = self._initial
        with Vertical(classes="dialog"):
            yield Label("Редактировать правило" if self._rule else "Добавить правило", classes="title")
            # a rule cannot change chain in place
            yield from _choice("Chain", "chain", list(CHAINS), init.chain, disabled=self._rule is not None)
            yield from _choice("Protocol", "protocol", list(PROTOCOLS), init.protocol)
            yield from _choice("Action", "action", list(ACTIONS), init.action)
            with Horizontal(classes="row"):
                yield Label("Source", classes="label")
                yield Input(init.source, placeholder="any или 192.168.1.0/24", id="source")
            with Horizontal(classes="row"):
                yield Label("Destination", classes="label")
                yield Input(init.destination, placeholder="any или 10.0.0.5", id="destination")
            with Horizontal(classes="row"):
                yield Label("Port", classes="label")
                yield Input(
                    init.port,
                    placeholder="22  ·  80,443  ·  1000:2000",
                    id="port",
                    disabled=init.protocol not in ("tcp", "udp"),
                )
            with Horizontal(classes="row"):
                yield Label("Journal", classes="label")
                yield Checkbox("писать срабатывания в журнал", init.log, id="log")
            yield Label("", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Сохранить", variant="success", id="save")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#source", Input).focus()

    @on(RadioSet.Changed, "#protocol")
    def _protocol_changed(self) -> None:
        port = self.query_one("#port", Input)
        port.disabled = _picked(self, "protocol") not in ("tcp", "udp")
        if port.disabled:
            port.value = ""

    @on(Input.Submitted)
    def _submitted(self) -> None:
        self._save()

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        raw = NewRule(
            _picked(self, "chain"),
            _picked(self, "protocol"),
            _picked(self, "action"),
            self.query_one("#source", Input).value,
            self.query_one("#destination", Input).value,
            self.query_one("#port", Input).value,
            self.query_one("#log", Checkbox).value,
        )
        try:
            rule = raw.validated()
        except ValueError as exc:
            self.query_one("#error", Label).update(str(exc))
            return
        self.dismiss(rule)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class TemplateScreen(ModalScreen[Optional[NewRule]]):
    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Шаблоны правил", classes="title")
            yield OptionList(*[Option(name, id=str(i)) for i, (name, _) in enumerate(TEMPLATES)])
            yield Label("Enter или клик — добавить правило", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    @on(OptionList.OptionSelected)
    def _selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(TEMPLATES[event.option_index][1])

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape,n", "no", "Нет"), Binding("y", "yes", "Да")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Удалить правило?", classes="title")
            yield Label(self._question, classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Удалить", variant="error", id="yes")
                yield Button("Отмена", id="no")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


def rule_summary(rule: Rule) -> str:
    parts = [f"#{rule.index} {rule.chain}", rule.protocol]
    if rule.source:
        parts.append(f"src {rule.source}")
    if rule.destination:
        parts.append(f"dst {rule.destination}")
    if rule.port:
        parts.append(f"port {rule.port}")
    parts.append(rule.action)
    return "  ".join(parts)


FILTERS = (None,) + CHAINS  # None = all chains
COLUMNS = ("time", "chain", "protocol", "source", "destination", "port", "action")
POLL_SECONDS = 3.0


class JournalTable(DataTable):
    BINDINGS = [
        Binding("left", "screen.prev_filter", show=False),
        Binding("right", "screen.next_filter", show=False),
    ]


class JournalScreen(Screen):
    """Rule hits read back from the kernel log, newest first."""

    BINDINGS = [Binding("escape,q,f7", "back", "К правилам")]

    def __init__(self, firewall) -> None:
        super().__init__()
        self.fw = firewall
        self.filter: Optional[str] = None
        self._entries: List[LogEntry] = []
        self._source = ""
        self._error = ""
        self._why_empty = ""
        self._shown: Optional[List[LogEntry]] = None

    def compose(self) -> ComposeResult:
        with Horizontal(id="jbar"):
            for chain in FILTERS:
                yield ToolButton(chain or "Все", id=f"jf-{chain or 'ALL'}", classes="jfilter")
            yield Static("", classes="spacer")
            yield ToolButton("Esc ← К правилам", id="jback", variant="primary")
        table = JournalTable(id="jtable", cursor_type="row", zebra_stripes=True)
        table.cursor_foreground_priority = "renderable"
        yield table
        yield Static("", id="jstatus")

    def on_mount(self) -> None:
        table = self.query_one("#jtable", JournalTable)
        for name in COLUMNS:
            table.add_column(name, key=name)
        table.focus()
        self._mark_filter()
        self.set_interval(POLL_SECONDS, self._poll)
        self.run_worker(self._poll())

    async def _poll(self) -> None:
        try:
            self._source, self._entries = await asyncio.to_thread(self.fw.read_journal, self.filter)
            self._error = ""
            self._why_empty = "" if self._entries else await self._explain_empty()
        except FirewallError as exc:
            self._error = str(exc)
        self._redraw()

    async def _explain_empty(self) -> str:
        """Tell the user why there is nothing to show instead of leaving a blank table."""
        try:
            rules, hits, state = await asyncio.to_thread(self.fw.log_diagnosis)
        except FirewallError:
            return "Записей нет."
        if not rules:
            return "Записей нет: журнал не включён ни у одного правила. Включите «Journal» в окне правила (F1 / e)."
        if not hits:
            return (
                f"Записей нет: правил с журналом {rules}, но они ещё ни разу не сработали (0 пакетов). "
                "Проверьте порядок правил и счётчик Pkts: пакет должен дойти до правила."
            )
        head = f"Записей нет, хотя правила сработали ({hits} пакетов): "
        if state not in (None, "active"):
            return (
                head + f"служба linfw-logd не работает (состояние: {state}). "
                "Запустите: systemctl enable --now linfw-logd; причина: journalctl -u linfw-logd"
            )
        return (
            head + "служба linfw-logd ничего не записала. Проверьте journalctl -u linfw-logd: "
            "возможно, не загружен модуль nfnetlink_log (в контейнере его загружают на хосте: modprobe nfnetlink_log)."
        )

    def _mark_filter(self) -> None:
        for chain in FILTERS:
            self.query_one(f"#jf-{chain or 'ALL'}", ToolButton).set_class(chain == self.filter, "active")

    def _redraw(self) -> None:
        table = self.query_one("#jtable", JournalTable)
        shown = list(reversed(self._entries))  # the reader already applied the chain filter
        if shown != self._shown:
            row, scroll = table.cursor_row, table.scroll_y
            table.clear()
            table.add_rows(
                (
                    e.time,
                    e.chain.lower(),
                    e.protocol,
                    e.source,
                    e.destination,
                    e.port,
                    Text(e.action, style=ACTION_STYLE.get(e.action, "bold")),
                )
                for e in shown
            )
            if shown:
                table.move_cursor(row=min(row, len(shown) - 1), animate=False)
            table.scroll_y = scroll
            self._shown = shown
        status = self.query_one("#jstatus", Static)
        if self._error:
            status.update(Text(self._error, style="bold #ff5555"))
        elif not self._entries:
            status.update(self._why_empty or "Записей нет.")
        else:
            count = f"последние {MAX_ENTRIES}" if len(shown) >= MAX_ENTRIES else str(len(shown))
            status.update(
                f"Источник: {self._source}  ·  записей: {count}  ·  хранится {RETENTION_DAYS} дн."
                "  ·  ←→ цепочка  ·  Esc назад"
            )

    def _set_filter(self, chain: Optional[str]) -> None:
        self.filter = chain
        self._shown = None
        self._mark_filter()
        self.run_worker(self._poll(), exclusive=True)

    @on(Button.Pressed, ".jfilter")
    def _filter_pressed(self, event: Button.Pressed) -> None:
        name = (event.button.id or "jf-ALL")[3:]
        self._set_filter(None if name == "ALL" else name)

    def action_next_filter(self) -> None:
        self._set_filter(FILTERS[(FILTERS.index(self.filter) + 1) % len(FILTERS)])

    def action_prev_filter(self) -> None:
        self._set_filter(FILTERS[(FILTERS.index(self.filter) - 1) % len(FILTERS)])

    @on(Button.Pressed, "#jback")
    def action_back(self) -> None:
        self.app.pop_screen()
