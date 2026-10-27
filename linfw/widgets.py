from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget

SELECTED = "bold white on #388bfd"
IDLE = "#aab4c0"
SEPARATOR = "#3a4654"


class Segmented(Widget, can_focus=True):
    """One-of-N choice drawn as a row of segments: ` INPUT │ OUTPUT │ FORWARD `.

    Click a segment or focus the control and use ←/→. `styles_by_value` gives a
    selected segment its own colour (e.g. green for accept)."""

    DEFAULT_CSS = """
    Segmented { width: auto; height: 1; }
    Segmented:disabled { opacity: 0.5; }
    """
    BINDINGS = [
        Binding("left", "step(-1)", show=False),
        Binding("right", "step(1)", show=False),
    ]

    value = reactive("", init=False)

    class Changed(Message):
        def __init__(self, segmented: "Segmented", value: str) -> None:
            super().__init__()
            self.segmented = segmented
            self.value = value

        @property
        def control(self) -> "Segmented":
            return self.segmented

    def __init__(
        self,
        options: Sequence[Tuple[str, str]],
        value: str,
        *,
        styles_by_value: Optional[Dict[str, str]] = None,
        id: Optional[str] = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(id=id, disabled=disabled)
        self.options = list(options)  # (value, label)
        self.styles_by_value = styles_by_value or {}
        self.set_reactive(Segmented.value, value)

    def render(self) -> Text:
        out = Text(no_wrap=True)
        for i, (val, label) in enumerate(self.options):
            selected = val == self.value
            style = self.styles_by_value.get(val, SELECTED) if selected else IDLE
            if selected and self.has_focus:
                style += " underline"
            out.append(f" {label} ", style=style)
            if i < len(self.options) - 1:
                out.append("│", style=SEPARATOR)
        return out

    def get_content_width(self, container, viewport) -> int:
        return sum(len(label) + 2 for _, label in self.options) + len(self.options) - 1

    def watch_value(self, value: str) -> None:
        self.refresh()
        self.post_message(self.Changed(self, value))

    def watch_has_focus(self, _focused: bool) -> None:
        self.refresh()

    def action_step(self, delta: int) -> None:
        values = [v for v, _ in self.options]
        index = values.index(self.value) if self.value in values else 0
        self.value = values[max(0, min(len(values) - 1, index + delta))]

    def on_click(self, event: events.Click) -> None:
        x = 0
        for val, label in self.options:
            width = len(label) + 2
            if x <= event.x < x + width:
                self.value = val
                return
            x += width + 1
