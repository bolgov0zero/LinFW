"""The «Списки» window: named address lists that rules use as `@name`."""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List, Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from . import lists as lst
from .model import FirewallError
from .screens import ConfirmScreen, ToolButton, key_label
from .theme import BLUE, ORANGE, RED


class NewListScreen(ModalScreen[Optional[str]]):
    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Новый список", classes="title")
            with Horizontal(classes="row"):
                yield Label("Название", classes="label")
                yield Input(placeholder="например office", id="name")
            yield Label("", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Создать", variant="success", id="ok")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#error", Label).display = False
        self.query_one("#name", Input).focus()

    @on(Input.Submitted)
    @on(Button.Pressed, "#ok")
    def _create(self) -> None:
        error = self.query_one("#error", Label)
        try:
            name = lst.check_name(self.query_one("#name", Input).value)
        except ValueError as exc:
            error.update(str(exc))
            error.display = True
            return
        self.dismiss(name)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class AddAddressesScreen(ModalScreen[Optional[List[str]]]):
    """Paste addresses: one per line, or separated by spaces, commas or semicolons."""

    BINDINGS = [Binding("escape", "cancel", "Отмена")]

    def __init__(self, list_name: str) -> None:
        super().__init__()
        self._list_name = list_name

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label(f"Добавить адреса в @{self._list_name}", classes="title")
            yield TextArea(id="text")
            yield Label("IP-адреса и сети, по одному в строке или через пробел/запятую: 10.0.0.5, 192.168.1.0/24", classes="hint")
            yield Label("", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Добавить", variant="success", id="ok")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#error", Label).display = False
        self.query_one(TextArea).focus()

    @on(Button.Pressed, "#ok")
    def _apply(self) -> None:
        error = self.query_one("#error", Label)
        good, problems = lst.parse_entries(self.query_one(TextArea).text)
        if problems or not good:
            shown = problems[:3] + (["…"] if len(problems) > 3 else []) or ["Введите хотя бы один адрес"]
            error.update("\n".join(shown))
            error.display = True
            return
        self.dismiss(good)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ListsScreen(Screen):
    """Lists on the left, the addresses of the selected list on the right."""

    BINDINGS = [
        Binding("escape,q,f8", "back", "К правилам"),
        Binding("n", "new_list", show=False),
        Binding("a,insert", "add_entries", show=False),
        Binding("x", "delete_list", show=False),
        Binding("delete", "delete_entry", show=False),
    ]

    def __init__(self, firewall) -> None:
        super().__init__()
        self.fw = firewall
        self._data: Dict[str, List[str]] = {}
        self._usage: Dict[str, List[str]] = {}
        self._error = ""
        self._persistent = True
        self._current: Optional[str] = None

    def compose(self) -> ComposeResult:
        with Horizontal(id="lbar"):
            yield ToolButton(key_label("N", "Новый список"), id="l-new")
            yield ToolButton(key_label("A", "Добавить адреса"), id="l-add")
            yield Static("│", classes="sep")
            yield ToolButton(key_label("X", "Удалить список"), id="l-del")
            yield ToolButton(key_label("Del", "Удалить адрес"), id="l-delentry")
            yield Static("", classes="spacer")
            yield ToolButton(key_label("Esc", "← К правилам"), id="l-back")
        with Horizontal(id="lists-pane"):
            lists = DataTable(id="lists", cursor_type="row", zebra_stripes=True)
            lists.border_title = "Списки"
            entries = DataTable(id="entries", cursor_type="row", zebra_stripes=True)
            entries.border_title = "Адреса"
            yield lists
            yield entries
        yield Static("", id="lstatus")

    def on_mount(self) -> None:
        lists, entries = self.query_one("#lists", DataTable), self.query_one("#entries", DataTable)
        lists.add_column("Список", key="name")
        lists.add_column("Адресов", key="count")
        lists.add_column("В правилах", key="used")
        entries.add_column("Адрес", key="addr")
        lists.focus()
        self.run_worker(self._reload())

    # -- data ------------------------------------------------------------

    async def _reload(self, select: Optional[str] = None) -> None:
        try:
            self._data = await asyncio.to_thread(self.fw.lists)
            self._usage = await asyncio.to_thread(self.fw.list_usage)
            self._persistent = await asyncio.to_thread(self.fw.lists_persistent)
            self._error = ""
        except FirewallError as exc:
            self._data, self._usage, self._error = {}, {}, str(exc)
        if select:
            self._current = select
        if self._current not in self._data:
            self._current = next(iter(self._data), None)
        self._draw_lists()

    def _draw_lists(self) -> None:
        table = self.query_one("#lists", DataTable)
        table.clear()
        for name, entries in self._data.items():
            used = len(self._usage.get(name, []))
            table.add_row(
                Text(f"@{name}", style=f"bold {BLUE}"),
                Text(str(len(entries)), justify="right"),
                Text(f"{used} прав." if used else "—", style="" if used else "dim"),
                key=name,
            )
        if self._current in self._data:
            table.move_cursor(row=list(self._data).index(self._current), animate=False)
        self._draw_entries()

    def _draw_entries(self) -> None:
        table = self.query_one("#entries", DataTable)
        row = table.cursor_row
        table.clear()
        entries = self._data.get(self._current or "", [])
        for entry in entries:
            table.add_row(entry, key=entry)
        if entries:
            table.move_cursor(row=min(row, len(entries) - 1), animate=False)
        table.border_title = f"Адреса @{self._current} ({len(entries)})" if self._current else "Адреса"
        self._draw_status()

    def _draw_status(self) -> None:
        status = self.query_one("#lstatus", Static)
        if self._error:
            status.update(Text(f"Списки недоступны: {self._error}", style=f"bold {RED}"))
        elif not self._persistent:
            status.update(Text("Внимание: пакет ipset-persistent не установлен, списки пропадут после перезагрузки.", style=f"bold {ORANGE}"))
        elif not self._data:
            status.update("Списков пока нет. N — создать первый, потом A — добавить в него адреса.")
        else:
            used = self._usage.get(self._current or "", [])
            where = f"Используется в: {', '.join(used)}" if used else "В правилах не используется"
            status.update(f"{where}   ·   Tab — переключить панель   ·   Esc назад")

    @on(DataTable.RowHighlighted, "#lists")
    def _list_highlighted(self, event: DataTable.RowHighlighted) -> None:
        name = event.row_key.value if event.row_key else None
        if name in self._data and name != self._current:
            self._current = name
            self.query_one("#entries", DataTable).move_cursor(row=0, animate=False)
            self._draw_entries()

    # -- actions ---------------------------------------------------------

    async def _do(self, message: Callable[[Any], str], op: Callable[[], Any], select: Optional[str] = None) -> None:
        """Run a change off the UI thread, save it, show the result and re-read the lists."""
        try:
            result = await asyncio.to_thread(op)
        except FirewallError as exc:
            self.notify(str(exc), severity="error", timeout=8)
            return
        try:
            await asyncio.to_thread(self.fw.persist)
        except FirewallError as exc:
            self.notify(str(exc), severity="warning", timeout=8)
        self.notify(message(result))
        await self._reload(select)

    @on(Button.Pressed, "#l-new")
    def action_new_list(self) -> None:
        def done(name: Optional[str]) -> None:
            if name:
                self.run_worker(self._do(lambda _: f"Список «{name}» создан", lambda: self.fw.create_list(name), select=name))

        self.app.push_screen(NewListScreen(), done)

    @on(Button.Pressed, "#l-add")
    def action_add_entries(self) -> None:
        name = self._current
        if not name:
            self.notify("Сначала создайте список (N)", severity="warning")
            return

        def done(entries: Optional[List[str]]) -> None:
            if entries:
                self.run_worker(
                    self._do(lambda n: f"Новых адресов: {n}", lambda: self.fw.add_to_list(name, entries), select=name)
                )

        self.app.push_screen(AddAddressesScreen(name), done)

    @on(Button.Pressed, "#l-del")
    def action_delete_list(self) -> None:
        name = self._current
        if not name:
            return
        used = self._usage.get(name)
        if used:
            self.notify(f"Список «{name}» используется в правилах: {', '.join(used)}. Сначала измените или удалите их.", severity="error", timeout=8)
            return

        def done(confirmed: Optional[bool]) -> None:
            if confirmed:
                self.run_worker(self._do(lambda _: f"Список «{name}» удалён", lambda: self.fw.delete_list(name)))

        self.app.push_screen(
            ConfirmScreen(f"@{name}  ·  адресов: {len(self._data.get(name, []))}", "Удалить список?"), done
        )

    @on(Button.Pressed, "#l-delentry")
    def action_delete_entry(self) -> None:
        name = self._current
        table = self.query_one("#entries", DataTable)
        entries = self._data.get(name or "", [])
        if not name or not 0 <= table.cursor_row < len(entries):
            return
        entry = entries[table.cursor_row]
        self.run_worker(self._do(lambda _: f"Адрес {entry} удалён", lambda: self.fw.remove_from_list(name, [entry]), select=name))

    @on(Button.Pressed, "#l-back")
    def action_back(self) -> None:
        self.app.pop_screen()
