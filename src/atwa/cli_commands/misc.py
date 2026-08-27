"""Miscellaneous subcommands that don't fit the other groups."""

from __future__ import annotations


def _cmd_gui(args) -> int:
    """ATWA-NG's own desktop GUI (src/atwa/gui/). All its imports are
    relative (`from ..radio import ...` etc.) pointing at this
    package's own modules — see gui/app.py."""
    from ..gui.app import main as gui_main
    from ..gui.elevate import ensure_root

    ensure_root(demo=args.demo)  # no-op if already root or --demo; else re-execs under sudo and exits
    return gui_main(demo=args.demo)
