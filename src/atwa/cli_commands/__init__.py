"""Shared helpers and binary paths for ATWA-NG CLI subcommands."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Under a PyInstaller-frozen build, __file__ resolves inside the extracted
# _MEIPASS temp dir, not the repo tree — vendor/ isn't bundled into the
# onefile blob (its libtool wrapper scripts/symlinks don't survive
# relocation), so it ships as a sibling directory next to the executable
# instead. Resolve against the exe's own directory when frozen.
if getattr(sys, "frozen", False):
    _REPO_ROOT = Path(sys.executable).resolve().parent
else:
    _REPO_ROOT = Path(__file__).resolve().parents[3]
_VENDOR_ROOT = _REPO_ROOT / "vendor" / "aircrack-ng"
_WPSRECON_ROOT = _REPO_ROOT / "vendor" / "reaver" / "src"
# aireplay-ng (injection) is intentionally not listed here — native scapy
# injection (frames.py + attacks/deauth.py + injection_test.py) fully
# replaced it (2026-08-27), matching the project's policy that the only
# acceptable wrappers are cracking backends and cap/pcap-format tools.
# CAPCRACK_BIN fits that exemption (operates on capture files).
# WPSRECON_BIN (wash) does NOT — it's a real WPS wrapper, just not yet
# ported (see docs/vendor_inventory.md Phase 6e).
CAPCRACK_BIN = _VENDOR_ROOT / "aircrack-ng"
WPSRECON_BIN = _WPSRECON_ROOT / "wash"
EAPOLHUNTER_BIN = _REPO_ROOT / "vendor" / "eapol_hunter" / "eapol_hunter.py"
EAPOLDUMP_BIN = _REPO_ROOT / "vendor" / "eapol_dump" / "eapol_dump.sh"


def _python_for_scripts() -> str:
    if getattr(sys, "frozen", False):
        return shutil.which("python3") or "python3"
    return sys.executable


def _run_bounded(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """subprocess.run with no timeout is a real hang risk here: the
    injection engine prints "Waiting for beacon frame" and blocks
    indefinitely if the target BSSID never shows up on the current
    channel (wrong channel, AP gone, typo'd MAC). Bounded so that case
    fails cleanly instead of hanging the whole command forever."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        partial_out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return 1, partial_out, (
            f"timed out after {timeout}s — likely no beacon seen for the "
            f"target (wrong channel, AP not present, or bad BSSID)"
        )
