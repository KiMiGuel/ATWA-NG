"""Sudo self-relaunch — ported from v1's ensure_root() (main.py 4615-4642):
detect non-root, prompt for a password in a Tk dialog, re-exec under sudo.

One real improvement over v1's version: this explicitly passes XAUTHORITY
through to the re-exec'd root process, not just DISPLAY. Without it, root
can't open a window on the invoking user's X session at all (confirmed
live, 2026-08-19 — needed a manual `xhost +SI:localuser:root` workaround
to get a sudo-launched instance on screen). Passing the real XAUTHORITY
cookie authenticates properly without touching X access control at all.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def ensure_root(demo: bool) -> None:
    """No-op if already root or in --demo mode (demo never touches
    hardware, matching v1's `if not args.demo: ensure_root()`). Otherwise
    prompts for a sudo password and re-execs `python -m atwa.cli gui` as
    root, replacing this process's exit code with the re-exec'd one."""
    if demo or os.geteuid() == 0:
        return

    import tkinter as tk
    from tkinter import simpledialog

    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring(
        "ATWA-NG requires root", "Enter sudo password:", show="*", parent=root,
    )
    root.destroy()
    if not password:
        print("Root privileges are required.", file=sys.stderr)
        sys.exit(1)

    env = dict(os.environ)
    xauthority = Path.home() / ".Xauthority"
    if xauthority.exists():
        env["XAUTHORITY"] = str(xauthority)

    args = ["sudo", "-S", sys.executable, "-m", "atwa.cli", "gui"]
    proc = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    out, err = proc.communicate(input=password + "\n")
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(proc.returncode)
