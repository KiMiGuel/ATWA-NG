"""Miscellaneous subcommands that don't fit the other groups."""

from __future__ import annotations

import sys


def _cmd_update_check(args) -> int:
    from .. import __version__
    from ..update_check import check_for_update

    result = check_for_update(__version__, timeout=args.timeout)
    if result.error:
        print(f"update check failed: {result.error}", file=sys.stderr)
        return 1
    if result.update_available:
        print(f"ATWA-NG update available: {result.latest} (installed: {result.current})")
        if result.release_url:
            print(result.release_url)
        return 10
    print(f"ATWA-NG is up to date ({result.current})")
    return 0


def _cmd_gui(args) -> int:
    """ATWA-NG's own desktop GUI (src/atwa/gui/). All its imports are
    relative (`from ..radio import ...` etc.) pointing at this
    package's own modules — see gui/app.py."""
    from ..gui.app import main as gui_main
    from ..gui.elevate import ensure_root

    ensure_root(demo=args.demo)  # no-op if already root or --demo; else re-execs under sudo and exits
    return gui_main(demo=args.demo)
