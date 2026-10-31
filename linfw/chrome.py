"""The parts every screen shares: breadcrumb bar, meter, key hints and status bar."""
from __future__ import annotations

from typing import List, Sequence, Tuple

from rich.color import Color
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import Button, Static

from . import __version__
from .theme import AMBER, BACKGROUND, FAINT, GREEN, MUTED, PINK

def crumb(*parts: str) -> Text:
    """`iptables › INPUT`: the way to the current screen, the last step in pink."""
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, part in enumerate(parts):
        if i:
            out.append(" › ", style=FAINT)
        out.append(part, style=f"bold {PINK}" if i == len(parts) - 1 else MUTED)
    return out


def key_label(key: str, name: str) -> Text:
    """`F1 добавить`: the key in pink, what it does dimmed."""
    return Text.assemble((key, f"bold {PINK}"), " ", (name, MUTED))


def hints(*pairs: Tuple[str, str]) -> Text:
    """`tab поле · ⏎ сохранить · esc закрыть`: the hint line cut into the bottom border of a dialog."""
    out = Text(no_wrap=True)
    for i, (key, name) in enumerate(pairs):
        if i:
            out.append("  ")
        out.append_text(key_label(key, name))
    return out


def hint(key: str, name: str) -> Static:
    """A key hint that is not a button (arrows and the like)."""
    return Static(key_label(key, name), classes="keyhint")


def sep() -> Static:
    return Static("·", classes="sep")


def row(label: Text, value: Text, width: int) -> Text:
    """`label ........ value`, the value flush right."""
    out = Text(no_wrap=True, overflow="ellipsis")
    out.append_text(label)
    out.append(" " * max(1, width - label.cell_len - value.cell_len))
    out.append_text(value)
    return out


def fit_title(left: Text, right: Text, width: int) -> Text:
    """A border title with a second part pushed to the right edge, the gap drawn as border line.
    `width` is the width of the whole box; Textual keeps 2 cells at each end for corners and blanks."""
    room = width - 4
    gap = room - left.cell_len - right.cell_len - 2  # one blank beside each part
    out = Text(no_wrap=True)
    out.append_text(left)
    if gap < 1:
        return out
    out.append(" " + "─" * gap + " ", style=FAINT)
    out.append_text(right)
    return out


def _mix(a: str, b: str, f: float) -> str:
    ca, cb = Color.parse(a).get_truecolor(), Color.parse(b).get_truecolor()
    return "#" + "".join(f"{round(x + (y - x) * f):02x}" for x, y in zip(ca, cb))


def _shares(values: Sequence[int], cells: int) -> List[int]:
    """Split `cells` between the parts in proportion to their values (largest remainder),
    keeping at least one cell for every non-zero part."""
    total = sum(values)
    if not total or cells <= 0:
        return [0] * len(values)
    exact = [v / total * cells for v in values]
    out = [int(x) for x in exact]
    for i in sorted(range(len(values)), key=lambda i: exact[i] - out[i], reverse=True)[: cells - sum(out)]:
        out[i] += 1
    for i, v in enumerate(values):
        if v and not out[i]:
            out[out.index(max(out))] -= 1
            out[i] = 1
    return out


class TopBar(Horizontal):
    """Breadcrumb on the left, what is going on on the right, a thin rule underneath."""

    def __init__(self, *trail: str, status: Text | str = "") -> None:
        super().__init__(id="topbar")
        self._trail, self._status = trail, status

    def compose(self) -> ComposeResult:
        yield Static(crumb(*self._trail), id="crumb")
        yield Static(self._status, id="live")

    def set_trail(self, *trail: str) -> None:
        self.query_one("#crumb", Static).update(crumb(*trail))

    def set_status(self, status: Text | str) -> None:
        self.query_one("#live", Static).update(status)


class StatusBar(Horizontal):
    """`⚡ LinFW 0.1.0` · screen name · a few numbers."""

    def __init__(self, name: str, right: str = "") -> None:
        super().__init__(id="statusbar")
        self._name, self._right = name, right

    def compose(self) -> ComposeResult:
        yield Static(Text.assemble(("⚡ ", AMBER), ("LinFW", f"bold {GREEN}"), (f" {__version__}", MUTED)), id="sb-left")
        yield Static(self._name, id="sb-name")
        yield Static(Text(self._right, style=MUTED), id="sb-right")

    def set_right(self, text: str) -> None:
        self.query_one("#sb-right", Static).update(Text(text, style=MUTED))


class Meter(Widget):
    """A bar split between the parts (green/red/orange for the actions) and a caption under it."""

    DEFAULT_CSS = "Meter { height: 2; }"

    def __init__(self) -> None:
        super().__init__(id="meter")
        self._parts: List[Tuple[int, str]] = []
        self._pct = Text()
        self._left = Text()
        self._right = Text()

    def show(self, parts: Sequence[Tuple[int, str]], pct: Text, left: Text, right: Text) -> None:
        self._parts, self._pct, self._left, self._right = list(parts), pct, left, right
        self.refresh()

    def render(self) -> Text:
        width = max(self.size.width, 12)
        bar_w = max(width - self._pct.cell_len - 2, 4)
        bar = Text(no_wrap=True)
        shares = _shares([n for n, _ in self._parts], bar_w)
        if not any(shares):
            bar.append("╌" * bar_w, style=FAINT)
        for (_, color), n in zip(self._parts, shares):
            for i in range(n):  # a quiet gradient from the left end of the part to its right end
                bar.append("█", style=_mix(BACKGROUND, color, 0.6 + 0.4 * (i / max(n - 1, 1))))
        line1 = Text(no_wrap=True)
        line1.append_text(bar)
        line1.append("  ")
        line1.append_text(self._pct)
        line2 = Text(no_wrap=True, overflow="ellipsis")
        line2.append_text(self._left)
        line2.append(" " * max(2, width - self._left.cell_len - self._right.cell_len))
        line2.append_text(self._right)
        return Text("\n").join([line1, line2])


class ToolButton(Button, can_focus=False):
    """Footer and filter buttons never steal focus, so the arrow keys keep driving the table."""
