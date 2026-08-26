"""Capture storage conventions: where captures live on disk.

Ported from v1's capture_root()/sanitize_essid() (main.py:204-246) — this
is original layout/naming logic, not a tool wrapper, so it's carried over
directly rather than reimplemented. The path itself is a fixed convention
(~/hs/n2-ng) the user relies on across sessions; do not change it.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

VALID_CAPTURE_SUFFIXES = {".cap", ".pcap", ".pcapng"}
HASHCAT_22000_PREFIXES = ("WPA*01*", "WPA*02*")


def user_home() -> Path:
    """Return the invoking user's home directory even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd

            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except Exception:
            pass
    return Path.home()


def capture_root(create: bool = True) -> Path:
    """The fixed capture directory: ~/hs/n2-ng (real user home, not root's)."""
    root = user_home() / "hs" / "n2-ng"
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def sanitize_essid(essid: str, bssid: str) -> str:
    """Build a filesystem-safe per-target folder name: '<essid>_<bssid>'."""
    essid = (essid or "").strip()
    safe_bssid = bssid.replace(":", "-")
    if not essid or essid.lower().startswith("<length:"):
        return f"hidden_{safe_bssid}"
    safe = re.sub(r'[\\/:*?"<>|]', "", essid).replace(" ", "_")[:50]
    return f"{safe}_{safe_bssid}"


def target_capture_dir(essid: str | None, bssid: str, create: bool = True) -> Path:
    """Per-target capture folder: capture_root()/<essid>_<bssid>/."""
    path = capture_root(create=create) / sanitize_essid(essid or "", bssid)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def unique_path(path: Path) -> Path:
    """Return path, or a numbered variant if it already exists."""
    if not path.exists():
        return path
    for index in range(2, 1000):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    return path.with_name(f"{path.stem}_{int(time.time())}{path.suffix}")


def organized_output_path(kind: str, filename: str) -> Path:
    """A unique path under capture_root()/<kind>/YYYY-MM-DD/<filename>."""
    date_dir = time.strftime("%Y-%m-%d")
    path = capture_root() / kind / date_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return unique_path(path)


def is_supported_capture(path: Path) -> bool:
    return path.suffix.lower() in VALID_CAPTURE_SUFFIXES
