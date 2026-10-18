"""Vendored binary paths and bounded-subprocess helpers.

Lives at core level, not under cli_commands/, because attacks/wep_client.py
needs CHOPCHOP_BIN and importing a presentation-layer package to reach it
made cli_commands -> attacks -> cli_commands circular.

Resolution order for a binary (see :func:`resolve_binary`):

1. ``ATWA_<NAME>_PATH`` environment variable (explicit per-binary override)
2. ``ATWA_BIN_DIR`` environment variable (directory containing binaries)
3. Package data next to this module (``atwa/bin/<name>``, ``atwa/data/bin/<name>``)
   -- the location used by installed (wheel) packages
4. The development checkout's ``vendor/aircrack-ng/<name>``
5. ``shutil.which`` (system PATH, for optional fast backends)

Frozen builds resolve relative to the executable. The module-level
``CAPCRACK_BIN`` / ``CHOPCHOP_BIN`` constants are resolved once at import
time from the same chain, preserving the existing call sites.
"""

from __future__ import annotations

import os
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


def _env_name(name: str) -> str:
    return name.upper().replace("-", "_").replace(".", "_")


def resolve_binary(name: str) -> Path:
    """Resolve a native binary's path.

    Returns the first existing candidate in the resolution chain; if none
    exists, returns the package-data candidate so error messages point at
    the location a packaged install would populate.
    """
    candidates: list[Path] = []

    env_path = os.environ.get(f"ATWA_{_env_name(name)}_PATH")
    if env_path:
        candidates.append(Path(env_path))

    env_dir = os.environ.get("ATWA_BIN_DIR")
    if env_dir:
        candidates.append(Path(env_dir) / name)

    pkg_dir = Path(__file__).resolve().parent
    candidates.append(pkg_dir / "bin" / name)
    candidates.append(pkg_dir / "data" / "bin" / name)

    candidates.append(_VENDOR_ROOT / name)

    found = shutil.which(name)
    if found:
        candidates.append(Path(found))

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    # Nothing found: prefer the package-data location for the error message.
    return pkg_dir / "bin" / name


# Only cracking backends stay wrapped. Everything else is native: injection,
# scanning, handshake capture, WPS recon, and EAPOL capture/inspection.
# CHOPCHOP_BIN is the one attack-side exception -- the native rewrite in
# attacks/wep_client.py is verified broken and re-deriving KoreK/RC4 isn't
# worth it when the real implementation is already vendored.
CAPCRACK_BIN = resolve_binary("aircrack-ng")
CHOPCHOP_BIN = resolve_binary("aireplay-ng")


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