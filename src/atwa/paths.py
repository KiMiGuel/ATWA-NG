"""Vendored binary paths and bounded-subprocess helpers.

Lives at core level, not under cli_commands/, because attacks/wep_client.py
needs CHOPCHOP_BIN and importing a presentation-layer package to reach it
made cli_commands -> attacks -> cli_commands circular.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Frozen builds resolve vendor/ next to the executable: the onefile blob
# can't carry it (libtool wrapper symlinks don't survive relocation).
if getattr(sys, "frozen", False):
    _REPO_ROOT = Path(sys.executable).resolve().parent
else:
    _REPO_ROOT = Path(__file__).resolve().parents[2]
_VENDOR_ROOT = _REPO_ROOT / "vendor" / "aircrack-ng"

# Only cracking backends and capture/pcap tools stay wrapped. Every other
# capability is native: injection, scanning, handshake capture, WPS recon.
# CHOPCHOP_BIN is the one attack-side exception -- the native rewrite in
# attacks/wep_client.py is verified broken and re-deriving KoreK/RC4 isn't
# worth it when the real implementation is already vendored.
CAPCRACK_BIN = _VENDOR_ROOT / "aircrack-ng"
CHOPCHOP_BIN = _VENDOR_ROOT / "aireplay-ng"
EAPOLHUNTER_BIN = _REPO_ROOT / "vendor" / "eapol_hunter" / "eapol_hunter.py"
EAPOLDUMP_BIN = _REPO_ROOT / "vendor" / "eapol_dump" / "eapol_dump.sh"


def python_for_scripts() -> str:
    """Interpreter to run a vendored Python script with."""
    if getattr(sys, "frozen", False):
        return shutil.which("python3") or "python3"
    return sys.executable


def run_bounded(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """subprocess.run with a hard timeout, returning (rc, stdout, stderr).

    Without one, the injection engine prints "Waiting for beacon frame" and
    blocks forever when the target BSSID is absent (wrong channel, AP gone,
    typo'd MAC).
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return 1, partial, (
            f"timed out after {timeout}s — likely no beacon seen for the "
            f"target (wrong channel, AP not present, or bad BSSID)"
        )