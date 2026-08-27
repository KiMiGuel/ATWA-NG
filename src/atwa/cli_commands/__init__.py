"""Shared helpers and binary paths for ATWA-NG CLI subcommands."""

from __future__ import annotations

import subprocess
from pathlib import Path

_VENDOR_ROOT = Path(__file__).resolve().parents[2] / "vendor" / "aircrack-ng"
_WPSRECON_ROOT = Path(__file__).resolve().parents[2] / "vendor" / "reaver" / "src"
# aireplay-ng (injection) is intentionally not listed here — native scapy
# injection (frames.py + attacks/deauth.py + injection_test.py) fully
# replaced it (2026-08-27), matching the project's policy that the only
# acceptable wrappers are cracking backends and cap/pcap-format tools.
# CAPCRACK_BIN fits that exemption (operates on capture files).
# WPSRECON_BIN (wash) does NOT — it's a real WPS wrapper, just not yet
# ported (see docs/vendor_inventory.md Phase 6e).
CAPCRACK_BIN = _VENDOR_ROOT / "aircrack-ng"
WPSRECON_BIN = _WPSRECON_ROOT / "wash"


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
