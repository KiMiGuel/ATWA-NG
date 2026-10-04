"""ATWA-NG CLI subcommands.

Binary paths and the bounded-subprocess helper live in atwa.paths, at core
level: attacks/wep_client.py needs CHOPCHOP_BIN, and importing a
presentation-layer package to reach it made cli_commands <-> attacks
circular. They stay re-exported here because the subcommand modules import
them from this package.
"""

from __future__ import annotations

from ..paths import (
    CAPCRACK_BIN,
    CHOPCHOP_BIN,
)
from ..paths import run_bounded as _run_bounded

__all__ = [
    "CAPCRACK_BIN",
    "CHOPCHOP_BIN",
    "_run_bounded",
]