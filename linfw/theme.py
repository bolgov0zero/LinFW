"""One palette for the whole interface.

The same colours name an action everywhere (table, segments, journal, messages)
and feed Textual's own theme variables ($success, $error, $warning, $accent ...),
so stock widgets, dialogs and our CSS can never drift apart.
"""
from __future__ import annotations

from textual.theme import Theme

GREEN = "#3fb950"
RED = "#f85149"
ORANGE = "#f0883e"
BLUE = "#4c9aff"
MUTED = "#8b98a5"

ACTION_STYLE = {"accept": f"bold {GREEN}", "drop": f"bold {RED}", "reject": f"bold {ORANGE}"}
POLICY_STYLE = {"ACCEPT": GREEN, "DROP": RED, "REJECT": ORANGE}

LINFW_THEME = Theme(
    name="linfw",
    primary=BLUE,
    secondary=MUTED,
    accent=BLUE,
    success=GREEN,
    warning=ORANGE,
    error=RED,
    foreground="#d6dde5",
    background="#0e1319",
    surface="#141a22",
    panel="#1a222c",
    dark=True,
)
