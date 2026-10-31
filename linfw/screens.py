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

from .chrome import Meter, StatusBar, ToolButton, TopBar, hint, hints, key_label, sep  # noqa: F401
from .journal import MAX_ENTRIES, RETENTION_DAYS, LogEntry
from .theme import ACTION_COLOR, ACTION_STYLE, AMBER, GREEN, MUTED, ORANGE, PINK, RED
from .model import ACTIONS, CHAINS, PROTOCOLS, FirewallError, NewRule, Rule
from .widgets import Segmented


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if value < 1024 or unit == "ТБ":
            return f"{int(value)} {unit}" if unit == "Б" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} Б"


_VERB = {"accept": ("Разрешает", GREEN), "drop": ("Отбрасывает", RED), "reject": ("Отклоняет", ORANGE)}
_PROTOCOL = {"all": "весь трафик", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP (ping)"}


def _who(value: str) -> str:
    return f"списка «{value[1:]}»" if value.startswith("@") else value


def describe_rule(rule: "Rule", pkts: int, nbytes: int) -> Text:
    """One readable sentence about a rule: what it does, to whom, and how busy it is."""
    verb, colour = _VERB.get(rule.action, (rule.action, MUTED))
    what = _PROTOCOL.get(rule.protocol, rule.protocol)
    where = ""
    if rule.source:
        where += f" от {_who(rule.source)}"
    if rule.destination:
        where += f" к {_who(rule.destination)}"
    if rule.port:
        where += f", порт {rule.port}"
    out = Text()
    if not rule.enabled:
        out.append("выключено · ", style="dim")
    out.append(verb, style=f"bold {colour}")
    out.append(f" {what}{where}")
    if rule.extra:
        out.append(" (+ доп. условия)", style="dim")
    out.append(f"   ·   {humanize_count(pkts)} пакетов, {human_bytes(nbytes)}", style="dim")
    if rule.log:
        out.append("   ·   журнал ●", style="dim")
    return out


def humanize_count(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def dialog(title: str, *keys: Tuple[str, str], classes: str = "dialog") -> Vertical:
    """The frame every dialog shares: the title cut into the top border, the key hints into the bottom one."""
    box = Vertical(classes=classes)
    box.border_title = title
    box.border_subtitle = hints(*keys)
    return box


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

    def __init__(
        self,
        chain: str = "INPUT",
        rule: Optional[Rule] = None,
        lists: Optional[Dict[str, int]] = None,
        lists_problem: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._rule = rule  # set when editing an existing rule
        self._lists = lists or {}  # name -> number of addresses, for the «Список» button
        self._lists_problem = lists_problem
        self._initial = rule.to_new() if rule else NewRule(chain if chain in CHAINS else "INPUT")

    def compose(self) -> ComposeResult:
        init = self._initial
        with dialog(
            "Редактировать правило" if self._rule else "Добавить правило",
            ("tab", "поле"), ("◄/►", "вариант"), ("⏎", "сохранить"), ("esc", "закрыть"),
        ):
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
                yield Input(init.source, placeholder="any, 192.168.1.0/24 или @список", id="source")
                yield Button("Список ▾", id="pick-source", classes="pick")
            with Horizontal(classes="row"):
                yield Label("Destination", classes="label")
                yield Input(init.destination, placeholder="any, 10.0.0.5 или @список", id="destination")
                yield Button("Список ▾", id="pick-destination", classes="pick")
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
                yield Button("Сохранить", id="save")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#error", Label).display = False
        self.query_one("#source", Input).focus()

    @on(Button.Pressed, ".pick")
    def _pick_list(self, event: Button.Pressed) -> None:
        field = self.query_one("#" + (event.button.id or "pick-source")[5:], Input)
        if self._lists_problem:
            self.query_one("#error", Label).update(f"Списки недоступны: {self._lists_problem}")
            self.query_one("#error", Label).display = True
            return

        def chosen(name: Optional[str]) -> None:
            if name:
                field.value = "@" + name
            field.focus()

        self.app.push_screen(PickListScreen(self._lists), chosen)

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
        with dialog("Шаблоны правил", ("↑↓", "выбрать"), ("⏎", "добавить"), ("esc", "закрыть"), classes="dialog wide"):
            yield OptionList(*[Option(_template_prompt(n, r, width), id=str(i)) for i, (n, r) in enumerate(TEMPLATES)])
            with Horizontal(classes="buttons"):
                yield Button("Добавить", id="apply")
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


class PickListScreen(ModalScreen[Optional[str]]):
    """Choose one of the address lists for a rule's source or destination."""

    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def __init__(self, lists: Dict[str, int]) -> None:
        super().__init__()
        self._names = sorted(lists)
        self._counts = lists

    def compose(self) -> ComposeResult:
        width = max((len(n) for n in self._names), default=0)
        with dialog("Выберите список", ("↑↓", "выбрать"), ("⏎", "выбрать"), ("esc", "закрыть")):
            if self._names:
                yield OptionList(
                    *[
                        Option(
                            Text.assemble((f"@{n}".ljust(width + 1), "bold"), "   ", (f"{self._counts[n]} адресов", "dim")),
                            id=n,
                        )
                        for n in self._names
                    ]
                )
            else:
                yield Label("Списков пока нет. Создайте их в окне «Списки» (F8).", classes="hint")
            with Horizontal(classes="buttons"):
                if self._names:
                    yield Button("Выбрать", id="apply")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        if self._names:
            options = self.query_one(OptionList)
            options.highlighted = 0
            options.focus()

    @on(OptionList.OptionSelected)
    def _selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(self._names[event.option_index])

    @on(Button.Pressed, "#apply")
    def _apply(self) -> None:
        self.dismiss(self._names[self.query_one(OptionList).highlighted or 0])

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape,n", "no", "Нет"), Binding("y", "yes", "Да")]

    def __init__(self, question: str, title: str = "Удалить правило?") -> None:
        super().__init__()
        self._question = question
        self._title = title

    def compose(self) -> ComposeResult:
        with dialog(self._title, ("◄/►", "выбор"), ("⏎", "подтвердить"), ("y/n", "да/нет"), ("esc", "закрыть"), classes="dialog confirm"):
            yield Label(self._question, classes="question")
            with Horizontal(classes="buttons"):
                yield Button("Удалить", classes="danger", id="yes")
                yield Button("Отмена", id="no")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


HELP = (
    ("Правила", (("F1  a", "добавить"), ("Enter  e", "изменить"), ("F2  Del  x", "удалить"), ("F3  t", "шаблон"),
                 ("F4  u", "поднять"), ("F5  d", "опустить"), ("F6  Space", "выключить / включить"),
                 ("F7  j", "журнал"), ("F8  l", "списки"), ("←  →", "цепочка"), ("F10  q  Esc", "выход"))),
    ("Журнал", (("a  d  r", "accept / drop / reject"), ("←  →", "цепочка"), ("F5", "обновить снимок"),
                ("Esc  F7", "к правилам"))),
    ("Списки", (("N", "новый список"), ("A  Ins", "добавить адреса"), ("X", "удалить список"),
                ("Del", "удалить адрес"), ("Tab", "другая панель"), ("Esc  F8", "к правилам"))),
)


class HelpScreen(ModalScreen[None]):
    """Every key of every screen in one place."""

    BINDINGS = [Binding("escape,question_mark,q", "close", "Закрыть")]

    def compose(self) -> ComposeResult:
        with dialog("Клавиши", ("esc", "закрыть"), classes="dialog wide"):
            for title, keys in HELP:
                yield Label(title, classes="help-title")
                for key, what in keys:
                    yield Label(Text.assemble((key.ljust(12), f"bold {PINK}"), what), classes="help-row")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_click(self) -> None:
        self.dismiss(None)


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
        Binding("question_mark", "help", show=False),
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
        yield TopBar("linfw", "Журнал")
        yield Meter()
        filters = Horizontal(id="jbar")
        filters.border_title = "Фильтры"
        with filters:
            for chain in FILTERS:
                yield ToolButton(chain or "Все", id=f"jf-{chain or 'ALL'}", classes="jfilter")
            yield Static("│", classes="sep")
            for action in JOURNAL_ACTIONS:
                yield ToolButton(action, id=f"ja-{action}", classes=f"jaction {action}")
        table = JournalTable(id="jtable", cursor_type="row")
        table.cursor_foreground_priority = "renderable"
        yield table
        status = Static("", id="jstatus")
        status.border_title = "Состояние"
        yield status
        with Horizontal(id="helpbar"):
            yield hint("↑/↓", "выбор")
            yield sep()
            yield hint("←/→", "цепочка")
            yield sep()
            yield hint("a d r", "действие")
            yield sep()
            yield ToolButton(key_label("F5", "обновить"), id="jrefresh")
            yield sep()
            yield ToolButton(key_label("?", "ещё"), id="jhelp")
            yield sep()
            yield ToolButton(key_label("Esc", "← к правилам"), id="jback")
        yield StatusBar("Журнал")

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
        self._paint_header(shown)
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

    def _paint_header(self, shown: List[LogEntry]) -> None:
        """Bar, counts and the snapshot time: all of it describes what the filters let through."""
        counts = {a: sum(1 for e in shown if e.action == a) for a in JOURNAL_ACTIONS}
        left = Text()
        for i, action in enumerate(JOURNAL_ACTIONS):
            if i:
                left.append("  ·  ", style=MUTED)
            left.append(action, style=ACTION_COLOR[action])
            left.append(f" {counts[action]}", style="bold")
        self.query_one(Meter).show(
            [(counts[a], ACTION_COLOR[a]) for a in JOURNAL_ACTIONS],
            Text.assemble((str(len(shown)), "bold"), (" записей", MUTED)),
            left,
            Text(f"за {RETENTION_DAYS} дн., до {MAX_ENTRIES} записей", style=MUTED),
        )
        stamp = Text.assemble(("● ", AMBER), ("снимок, данные на ", MUTED), self._loaded) if self._loaded else Text("")
        self.query_one(TopBar).set_status(stamp)
        self.query_one(StatusBar).set_right(f"записей: {len(shown)}")
        self._subtitle()

    def _subtitle(self) -> None:
        table = self.query_one("#jtable", JournalTable)
        table.border_subtitle = f"Запись {table.cursor_row + 1} из {table.row_count}" if table.row_count else ""

    @on(DataTable.RowHighlighted, "#jtable")
    def _row_highlighted(self) -> None:
        self._subtitle()

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

    @on(Button.Pressed, "#jhelp")
    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    @on(Button.Pressed, "#jback")
    def action_back(self) -> None:
        self.app.pop_screen()
