"""Shared GUI layout constants.

These live apart from app.py so the seam mixins can import them without
a cycle: app.py inherits the mixins, so a mixin importing back from
app.py would be circular.
"""

from __future__ import annotations

TARGET_COLUMNS = (
    ("bssid", "BSSID", 165),
    ("ssid", "SSID", 220),
    ("channel", "CH", 45),
    ("security", "Security", 100),
    ("pmf", "PMF", 90),
    ("wps", "WPS", 75),
    ("signal", "Signal", 75),
)
# Column that absorbs leftover width instead of every column staying a
# fixed drag-only size (2026-08-28 user report: SSID text truncating while
# other columns sat on wasted space).
TARGET_STRETCH_COLUMN = "ssid"

CAPTURE_COLUMNS = (
    ("name", "File", 220),
    ("kind", "Kind", 90),
    ("size", "Size", 80),
    ("path", "Path", 420),
)
# Path is the column worth growing when there's slack width; the others
# are already sized to their content (same reasoning as TARGET_STRETCH_COLUMN).
CAPTURE_STRETCH_COLUMN = "path"

# Channel-lock discipline: selecting a target auto-locks the adapter to
# that target's channel so a background scan loop doesn't keep hopping
# away from it mid-attack; auto-unlock after this many seconds of the
# locked target going unseen, so a stale lock doesn't strand the radio
# on a dead channel forever.
CHANNEL_LOCK_TIMEOUT = 30.0