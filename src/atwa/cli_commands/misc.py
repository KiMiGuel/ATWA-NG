"""Miscellaneous subcommands that don't fit the other groups."""

from __future__ import annotations

import sys


def _cmd_update_check(args) -> int:
    from .. import __version__
    from ..update import apply_update, check_for_update

    result = check_for_update(__version__, timeout=args.timeout)
    if result.error:
        print(f"update check failed: {result.error}", file=sys.stderr)
        return 1
    if result.update_available:
        print(f"ATWA-NG update available: {result.latest} (installed: {result.current})")
        if result.release_url:
            print(result.release_url)
        print("Applying update...")
        ok, msg = apply_update()
        if ok:
            print(f"Update successful: {msg}")
            print("Restart ATWA-NG to use the new version.")
            return 0
        print(f"Update failed: {msg}", file=sys.stderr)
        return 1
    print(f"ATWA-NG is up to date ({result.current})")
    return 0


def _cmd_gui(args) -> int:
    """ATWA-NG's own desktop GUI (src/atwa/gui/). All its imports are
    relative (`from ..radio import ...` etc.) pointing at this
    package's own modules — see gui/app.py."""
    try:
        import tkinter as tk
    except ImportError:
        # Headless/minimal installs often ship Python without python3-tk.
        print("error: tkinter is not installed (install python3-tk), or use the CLI subcommands",
              file=sys.stderr)
        return 1
    from ..gui.app import main as gui_main
    from ..gui.elevate import ensure_root

    ensure_root(demo=args.demo)  # no-op if already root or --demo; else re-execs under sudo and exits
    try:
        return gui_main(demo=args.demo)
    except tk.TclError as exc:
        # `atwa gui` over SSH / in a container: tk.Tk() raises "no display
        # name and no $DISPLAY" -- neither RadioError nor OSError, so the
        # top-level handler let a raw traceback through on the exact
        # headless box the CLI exists to serve.
        print(f"error: GUI unavailable ({exc}) -- no display? Use the CLI subcommands or X forwarding",
              file=sys.stderr)
        return 1
