from __future__ import annotations

from typing import List, Optional

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, RadioButton, RadioSet
from textual.widgets.option_list import Option

from .model import ACTIONS, CHAINS, PROTOCOLS, NewRule, Rule

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
