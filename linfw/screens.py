from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from .journal import MAX_ENTRIES, RETENTION_DAYS, LogEntry
from .model import ACTIONS, CHAINS, PROTOCOLS, FirewallError, NewRule, Rule
from .widgets import Segmented

ACTION_STYLE = {"accept": "bold #2ecc71", "drop": "bold #ff5555", "reject": "bold #ff9f1a"}


class ToolButton(Button, can_focus=False):
    """Toolbar buttons never steal focus, so the arrow keys keep driving the table."""


TEMPLATES = [
    ("Открыть для всех SSH (порт 22)", NewRule("INPUT", "tcp", "ACCEPT", port="22")),
    ("Открыть для всех ICMP", NewRule("INPUT", "icmp", "ACCEPT")),
    ("Открыть для всех HTTP/HTTPS (порты 80, 443)", NewRule("INPUT", "tcp", "ACCEPT", port="80,443")),
]

# the selected action segment takes the action's colour, as in the rules table
ACTION_SEGMENT = {
    "ACCEPT": "bold #0b1f10 on #3fb950",
    "DROP": "bold #2b0a08 on #f85149",
    "REJECT": "bold #2b1405 on #f0883e",
}


def _choice(
    label: str,
    name: str,
    options: List[Tuple[str, str]],
    selected: str,
    disabled: bool = False,
    styles_by_value: Optional[Dict[str, str]] = None,
    classes: str = "row",
) -> ComposeResult:
    with Horizontal(classes=classes):
        yield Label(label, classes="label")
        yield Segmented(options, selected, id=name, disabled=disabled, styles_by_value=styles_by_value)


def _picked(dialog: ModalScreen, name: str) -> str:
    return dialog.query_one(f"#{name}", Segmented).value


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
            yield from _choice("Chain", "chain", [(c, c) for c in CHAINS], init.chain, disabled=self._rule is not None)
            yield from _choice("Protocol", "protocol", [(p, p) for p in PROTOCOLS], init.protocol)
            yield from _choice(
                "Action",
                "action",
                [(a, a.lower()) for a in ACTIONS],
                init.action,
                styles_by_value=ACTION_SEGMENT,
                classes="row gap",
            )
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
        self.query_one("#error", Label).display = False
        self.query_one("#source", Input).focus()

    @on(Segmented.Changed, "#protocol")
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
        error = self.query_one("#error", Label)
        try:
            rule = raw.validated()
        except ValueError as exc:
            error.update(str(exc))
            error.display = True
            return
        self.dismiss(rule)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


def _template_prompt(name: str, rule: NewRule, width: int) -> Text:
    """`name   tcp · 22 · accept`, with the action in its colour (the chain only if it is not INPUT)."""
    action = rule.action.lower()
    where = "" if rule.chain == "INPUT" else f"{rule.chain.lower()} · "
    return Text.assemble(
        name.ljust(width),
        "   ",
        (f"{where}{rule.protocol} · {rule.port or '-'} · ", "dim"),
        (action, ACTION_STYLE.get(action, "bold")),
    )


class TemplateScreen(ModalScreen[Optional[NewRule]]):
    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def compose(self) -> ComposeResult:
        width = max(len(name) for name, _ in TEMPLATES)
        with Vertical(classes="dialog wide"):
            yield Label("Шаблоны правил", classes="title")
            yield OptionList(*[Option(_template_prompt(n, r, width), id=str(i)) for i, (n, r) in enumerate(TEMPLATES)])
            yield Label("↑↓ выбрать · Enter или клик по пункту — добавить", classes="hint")
            with Horizontal(classes="buttons"):
                yield Button("Добавить", variant="success", id="apply")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        options = self.query_one(OptionList)
        options.highlighted = 0
        options.focus()

    @on(OptionList.OptionSelected)
    def _selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(TEMPLATES[event.option_index][1])

    @on(Button.Pressed, "#apply")
    def _apply(self) -> None:
        index = self.query_one(OptionList).highlighted
        self.dismiss(TEMPLATES[index or 0][1])

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
JOURNAL_ACTIONS = ("accept", "drop", "reject")
COLUMNS = ("time", "chain", "protocol", "source", "destination", "port", "action")
SNAPSHOT_LIMIT = 50_000  # records loaded at once; the filters then work on this snapshot


class JournalTable(DataTable):
    BINDINGS = [
        Binding("left", "screen.prev_filter", show=False),
        Binding("right", "screen.next_filter", show=False),
    ]


class JournalScreen(Screen):
    """Rule hits recorded by linfw-logd, newest first.

    The journal is a snapshot: it is read when the screen opens and again only when
    the user asks (F5 / «Обновить»). It never changes by itself, so the table does
    not move under the cursor while it is being read.

    Two independent filters work on that snapshot: the chain (one of Все / INPUT /
    OUTPUT / FORWARD) and the actions (any combination of accept / drop / reject,
    none = all). An entry is shown when it passes both."""

    BINDINGS = [
        Binding("escape,q,f7", "back", "К правилам"),
        Binding("f5,ctrl+r", "refresh_now", "Обновить"),
        Binding("a", "toggle_action('accept')", show=False),
        Binding("d", "toggle_action('drop')", show=False),
        Binding("r", "toggle_action('reject')", show=False),
    ]

    def __init__(self, firewall) -> None:
        super().__init__()
        self.fw = firewall
        self.filter: Optional[str] = None
        self.actions: Set[str] = set()
        self._snapshot: List[LogEntry] = []  # oldest first, as read
        self._source = ""
        self._error = ""
        self._why_empty = ""
        self._loaded = ""  # when the snapshot was taken
        self._shown: Optional[List[LogEntry]] = None
        self._seq = 0  # only the newest read may replace the snapshot

    def compose(self) -> ComposeResult:
        with Horizontal(id="jbar"):
            for chain in FILTERS:
                yield ToolButton(chain or "Все", id=f"jf-{chain or 'ALL'}", classes="jfilter")
            yield Static("│", classes="sep")
            for action in JOURNAL_ACTIONS:
                yield ToolButton(action, id=f"ja-{action}", classes="jaction")
            yield Static("", classes="spacer")
            yield ToolButton("F5 Обновить", id="jrefresh")
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
        self._mark_filters()
        self.run_worker(self._load())  # the only automatic read: when the journal opens

    async def _load(self) -> None:
        """Take a new snapshot (on open and on «Обновить»)."""
        self._seq += 1
        seq = self._seq
        try:
            source, entries = await asyncio.to_thread(self.fw.read_journal, None, None, SNAPSHOT_LIMIT)
            why = "" if entries else await self._explain_empty()
        except FirewallError as exc:
            if seq == self._seq:
                self._error = str(exc)
                self._redraw()
            return
        if seq != self._seq:  # F5 was pressed again meanwhile: the newer read wins
            return
        self._source, self._snapshot, self._error, self._why_empty = source, entries, "", why
        self._loaded = datetime.now().strftime("%H:%M:%S")
        self._shown = None
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

    def _mark_filters(self) -> None:
        for chain in FILTERS:
            self.query_one(f"#jf-{chain or 'ALL'}", ToolButton).set_class(chain == self.filter, "active")
        for action in JOURNAL_ACTIONS:
            self.query_one(f"#ja-{action}", ToolButton).set_class(action in self.actions, "active")

    def _visible(self) -> List[LogEntry]:
        """The snapshot through both filters, newest first, at most MAX_ENTRIES."""
        wanted = [
            e
            for e in reversed(self._snapshot)
            if self.filter in (None, e.chain) and (not self.actions or e.action in self.actions)
        ]
        return wanted[:MAX_ENTRIES]

    def _redraw(self) -> None:
        table = self.query_one("#jtable", JournalTable)
        shown = self._visible()
        if shown != self._shown:
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
                table.move_cursor(row=0, animate=False)
            table.scroll_y = 0
            self._shown = shown
        status = self.query_one("#jstatus", Static)
        stamp = f"данные на {self._loaded}" if self._loaded else ""
        if self._error:
            status.update(Text(self._error, style="bold #ff5555"))
        elif not self._snapshot:
            status.update(f"{self._why_empty or 'Записей нет.'}  ·  {stamp}")
        elif not shown:
            status.update(f"Под выбранные фильтры записей нет.  ·  {stamp}")
        else:
            count = f"последние {MAX_ENTRIES}" if len(shown) >= MAX_ENTRIES else str(len(shown))
            status.update(
                f"{self._source}  ·  записей: {count} (за {RETENTION_DAYS} дн.)  ·  {stamp}"
                "  ·  ←→ цепочка  ·  a d r действие  ·  F5 обновить"
            )

    def _refilter(self) -> None:
        self._mark_filters()
        self._redraw()  # filters only re-sort what is already loaded; nothing is read

    def _set_filter(self, chain: Optional[str]) -> None:
        self.filter = chain
        self._refilter()

    @on(Button.Pressed, ".jfilter")
    def _filter_pressed(self, event: Button.Pressed) -> None:
        name = (event.button.id or "jf-ALL")[3:]
        self._set_filter(None if name == "ALL" else name)

    @on(Button.Pressed, ".jaction")
    def _action_pressed(self, event: Button.Pressed) -> None:
        self.action_toggle_action((event.button.id or "")[3:])

    def action_toggle_action(self, action: str) -> None:
        self.actions.symmetric_difference_update({action})
        self._refilter()

    def action_next_filter(self) -> None:
        self._set_filter(FILTERS[(FILTERS.index(self.filter) + 1) % len(FILTERS)])

    def action_prev_filter(self) -> None:
        self._set_filter(FILTERS[(FILTERS.index(self.filter) - 1) % len(FILTERS)])

    @on(Button.Pressed, "#jrefresh")
    def action_refresh_now(self) -> None:
        self.run_worker(self._load(), exclusive=True)

    @on(Button.Pressed, "#jback")
    def action_back(self) -> None:
        self.app.pop_screen()
