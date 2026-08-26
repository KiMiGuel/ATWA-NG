"""Persistent GUI settings — JSON at ~/.config/atwa/settings.json.

JSON with defaults+merge, chowned back to the real user under sudo so
the config file isn't left root-owned, built against this project's
own storage.user_home().
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..storage import user_home

DEFAULTS: dict = {
    "wordlist": "",
    "capture_dir": "",  # empty = use storage.capture_root() default
    "adapter": "",
    "security_filter": "All",
    "randomize_mac": True,
    "sort_col": None,
    "sort_reverse": False,
    "hidden_columns": [],
}


def settings_path() -> Path:
    return user_home() / ".config" / "atwa" / "settings.json"


class Settings:
    def __init__(self):
        self.path = settings_path()
        self.data: dict = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            saved = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        self.data.update({k: v for k, v in saved.items() if k in DEFAULTS})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2))
        self._chown_to_real_user()

    def _chown_to_real_user(self) -> None:
        """If running under sudo, hand ownership back to the real user —
        otherwise the config dir/file ends up root-owned and unwritable
        next time the GUI runs unprivileged."""
        sudo_user = os.environ.get("SUDO_USER")
        if os.geteuid() != 0 or not sudo_user:
            return
        try:
            import pwd

            pw = pwd.getpwnam(sudo_user)
            os.chown(self.path, pw.pw_uid, pw.pw_gid)
            os.chown(self.path.parent, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        self.data[key] = value
