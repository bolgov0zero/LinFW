"""One palette for the whole interface.

The same colours name an action everywhere (table, bars, journal, messages)
and feed Textual's own theme variables ($success, $error, $warning, $accent ...),
so stock widgets, dialogs and our CSS can never drift apart. The extra colours
of the deep-blue look (pink focus, dim blue-grey text, panel lines) are theme
variables too: $pink, $violet, $amber, $dim, $faint, $line, $line-soft.
"""
from __future__ import annotations

from textual.theme import Theme

GREEN = "#4fdc7f"
RED = "#ff5d6c"
ORANGE = "#f39a45"
BLUE = "#5aa8ff"
PINK = "#d86be0"
VIOLET = "#a98bff"
AMBER = "#ecb44f"
MUTED = "#6a74a6"  # dim labels and hints
FAINT = "#3a4380"  # separators, empty parts of bars
LINE = "#2e3677"  # borders of idle panels
LINE_SOFT = "#232a5e"
TEXT = "#cdd5f7"
BACKGROUND = "#080a26"

ACTION_STYLE = {"accept": f"bold {GREEN}", "drop": f"bold {RED}", "reject": f"bold {ORANGE}"}
ACTION_COLOR = {"accept": GREEN, "drop": RED, "reject": ORANGE}
POLICY_STYLE = {"ACCEPT": GREEN, "DROP": RED, "REJECT": ORANGE}

LINFW_THEME = Theme(
    name="linfw",
    primary=PINK,
    secondary=MUTED,
    accent=BLUE,
    success=GREEN,
    warning=ORANGE,
    error=RED,
    foreground=TEXT,
    background=BACKGROUND,
    surface="#0b0e33",
    panel="#10143f",
    dark=True,
    variables={
        "pink": PINK,
        "violet": VIOLET,
        "amber": AMBER,
        "dim": MUTED,
        "faint": FAINT,
        "line": LINE,
        "line-soft": LINE_SOFT,
    },
)
