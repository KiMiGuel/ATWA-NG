"""Capture storage conventions: where captures live on disk.

The path is a fixed convention (~/atwa-hs) so it's stable across
sessions and renames going forward.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Sequence
from pathlib import Path

VALID_CAPTURE_SUFFIXES = {".cap", ".pcap", ".pcapng"}

# Target folders are named ``<essid>_<aa-bb-cc-dd-ee-ff>``.  Derived files
# under ``fixed/``, ``merged/``, etc. no longer live below that folder, so
# their names must carry the BSSID too; otherwise aircrack-ng cannot recover
# the target from the path and the GUI has to ask for it interactively.
_BSSID_RE = re.compile(
    r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f])",
    re.IGNORECASE,
)


def user_home() -> Path:
    """Return the invoking user's home directory even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd

            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, OSError):
            pass
    return Path.home()


def capture_root(create: bool = True) -> Path:
    """The fixed capture directory: ~/atwa-hs (real user home, not root's)."""
    root = user_home() / "atwa-hs"
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


def normalize_bssid(value: str) -> str | None:
    """Return a canonical lowercase BSSID, or ``None`` if it is not one."""
    match = _BSSID_RE.search(value or "")
    return match.group(1).replace("-", ":").lower() if match else None


def bssid_from_path(path: str | Path) -> str | None:
    """Find the target BSSID encoded in a capture path or filename.

    Native captures are stored below ``<essid>_<BSSID>`` folders.  Derived
    files (fixed/merged) may be elsewhere, so inspect the filename and every
    parent component, not only the immediate parent.  Returning ``None`` is
    intentional for user-supplied legacy paths; callers that need a target
    must decide whether to reject or prompt for it.
    """
    path = Path(path)
    for component in (path.name, *reversed(path.parts)):
        bssid = normalize_bssid(component)
        if bssid:
            return bssid
    return None


def bssids_from_paths(paths: Sequence[str | Path]) -> set[str]:
    """Return all distinct BSSIDs discoverable from ``paths``.

    Takes a Sequence rather than a list: this only ever iterates, and `list`
    is invariant, so a `list[str]` argument (what gui/app.py actually holds
    from its file dialog) is not a subtype of `list[str | Path]` even though
    every element is compatible.
    """
    return {bssid for path in paths if (bssid := bssid_from_path(path))}


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


def record_cracked_password(directory: Path, tool: str, identifier: str, password: str) -> Path:
    """Append a cracked-password record to <directory>/creds.json.

    Kept next to the handshake it was cracked from, per the existing
    per-target folder convention, rather than a separate results store.
    """
    creds_file = Path(directory) / "creds.json"
    try:
        records = json.loads(creds_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        records = []
    records.append({
        "tool": tool,
        "identifier": identifier,
        "password": password,
        "cracked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    })
    creds_file.write_text(json.dumps(records, indent=2) + "\n")
    return creds_file
