"""Sudo self-relaunch: detect non-root, prompt for a password in a Tk
dialog, re-exec under sudo.

Explicitly passes XAUTHORITY through to the re-exec'd root process, not
just DISPLAY. Without it, root
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


def _sudo_cached() -> bool:
    """True when `sudo` already holds valid cached credentials (or the user is
    NOPASSWD), so it won't prompt. `sudo -n true` succeeds without a password
    only while the credential timestamp is still fresh."""
    proc = subprocess.run(
        ["sudo", "-n", "true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def ensure_root(demo: bool) -> None:
    """No-op if already root or in --demo mode (demo never touches
    hardware). Otherwise re-execs `python -m atwa.cli gui` as root,
    replacing this process's exit code with the re-exec'd one.

    If `sudo` already has cached credentials the re-exec runs quietly (like a
    cached terminal `sudo`) with no prompt. Otherwise a Tk dialog asks for the
    password and feeds it to `sudo -S`.
    """
    if demo or os.geteuid() == 0:
        return

    # Root can't see this (typically `--user` editable) install, so hand the
    # module path to the re-exec explicitly. sudo's env_reset strips an
    # inherited PYTHONPATH, so pass it inline on the command line where it
    # survives. Harmless if atwa is already system-installed (root finds it
    # directly) or if there is nothing extra to add.
    env = dict(os.environ)
    xauthority = Path.home() / ".Xauthority"
    if xauthority.exists():
        env["XAUTHORITY"] = str(xauthority)

    import site

    import atwa as _atwa_pkg

    src_dir = os.path.dirname(os.path.dirname(_atwa_pkg.__file__))
    usersite = site.getusersitepackages()
    extra = os.pathsep.join([src_dir, usersite, env.get("PYTHONPATH", "")])
    py_path = f"PYTHONPATH={extra}"

    cached = _sudo_cached()
    if not cached:
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
        sudo_input = password + "\n"
    else:
        sudo_input = None

    args = ["sudo", "-n" if cached else "-S", py_path, sys.executable, "-m", "atwa.cli", "gui"]
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE if sudo_input else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        out, err = proc.communicate(input=sudo_input, timeout=3600)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        err = (err or "") + "\nroot GUI launch timed out after 3600 seconds"
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(124)
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(proc.returncode)
