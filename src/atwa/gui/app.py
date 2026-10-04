"""ATWA-NG GUI — Tkinter, wired to this project's own native attack
functions throughout (never subprocess-wraps an attack tool; John/
hcxpcapngtool/pcapfix/mergecap are generic file-format utilities, not
attack logic).

Design constraint driving the layout: a toolbar of many buttons in a
single `pack(side=LEFT)` row with no wrap and no menu fallback means
buttons past the window edge become inaccessible when narrowed. Every
action here is reachable from a real `tk.Menu` menu bar (native window
chrome — cannot be clipped by resizing, unlike a packed Frame), with
the toolbar reduced to a few essential, low-count controls so it's
unlikely to overflow even on its own.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk

from .. import __version__
from ..scan import AccessPoint
from . import theme as theme_mod
from .attacks import AttacksMixin
from .captures import CapturesMixin
from .logpane import LogPaneMixin
from .targets import TargetsMixin
from .toolbar import ToolbarMixin


class App(
    ToolbarMixin,
    TargetsMixin,
    CapturesMixin,
    AttacksMixin,
    LogPaneMixin,
):
    """The ATWA-NG desktop application.

    Composition only: state lives in __init__ below, behaviour lives in the
    five seam mixins (toolbar/targets/captures/attacks/logpane). They are
    plain classes sharing one `self`, so no seam needs any of the others
    passed to it.
    """

    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.root.title(f"ATWA-NG — {__version__}")
        # Default to 1320x780, but never larger than the actual screen and
        # centered on it -- a hardcoded size bigger than the display (small
        # laptops, netbooks, anyone without a full-HD-or-larger monitor)
        # opened off-screen/clipped on first launch.
        screen_w, screen_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        win_w, win_h = min(1380, int(screen_w * 0.95)), min(860, int(screen_h * 0.92))
        self.root.geometry(f"{win_w}x{win_h}+{(screen_w - win_w) // 2}+{(screen_h - win_h) // 2}")
        self.root.minsize(min(760, win_w), min(560, win_h))
        self._set_window_icon()

        self.fonts = theme_mod.apply(root)
        self.THEME = theme_mod.THEME
        # White outline around the whole window (v1 reference look) -- Tk's
        # highlight ring is the only way to get a colored border on a
        # top-level window itself, as opposed to individual widgets.
        self.root.configure(highlightthickness=2, highlightbackground=self.THEME["border"],
                             highlightcolor=self.THEME["border"])

        self._queue: queue.Queue = queue.Queue()
        self._queue_coalesce_lock = threading.Lock()
        self._scan_update_queued = False
        self._pending_signal_sample: int | None = None
        self._signal_sample_queued = False
        self._busy = False
        self._captures_refreshing = False
        self.capture_buttons: list[ttk.Button] = []
        self._scanning = threading.Event()
        # Generation token for the scan loop: a fast Stop -> Start would
        # otherwise let the OLD loop thread (still mid-hop dwell when the
        # flag got cleared) see _scanning set again and keep running --
        # two loops, two sniffers, two hoppers fighting one radio.
        # _stop_scan bumps this; a stale-generation loop exits at its next
        # iteration check.
        self._scan_generation = 0
        self._stop_event = threading.Event()
        self._auto_deauth_thread: threading.Thread | None = None
        self._auto_deauth_client: str | None = None
        self._scan_thread: threading.Thread | None = None
        # Default no-op; _run_bg() replaces this with a real self._log-backed
        # callback for the duration of each attack it launches. Set here too
        # so callers that bypass _run_bg (auto-deauth, PINCER's own thread
        # setup before _run_bg's fn actually starts) never hit an
        # AttributeError referencing self._progress_fn before any attack
        # has run yet.
        self._progress_fn = lambda msg: None

        self.aps: dict[str, AccessPoint] = {}
        self.selected_bssid: str | None = None
        self._last_graphed_bssid: str | None = None
        self._select_capture_watch_stop: threading.Event | None = None
        self._lock_capture_proc = None  # capture.lock.LockCapture | None
        self._crack_proc_holder: dict = {}  # {"proc": subprocess.Popen} while a crack runs
        self.mon_iface: str | None = None
        self.own_mac: str | None = None
        self._permanent_mac: str | None = None  # set aside while MAC is randomized, for restore
        self.alfa_pair: tuple[str, str] | None = None  # (scan_iface, attack_iface) once detected

        from .settings import Settings

        self.settings = Settings()

        # Channel lock state — see CHANNEL_LOCK_TIMEOUT above.
        self.channel_locked = False
        self.locked_bssid: str | None = None
        self.locked_channel: int | None = None
        self._scan_channels: list[int] | None = None  # None = hop all; [ch] = locked
        self._lock_lost_since: float | None = None

        self.adapter_var = tk.StringVar()
        self.adapter_display_var = tk.StringVar()  # combobox text: "wlan1 (Mediatek)"; adapter_var stays the bare iface
        self.iface_ap_var = tk.StringVar(value=self.settings.get("iface_ap", ""))
        self.iface_ap_display_var = tk.StringVar()
        self._iface_display_to_name: dict[str, str] = {}
        self._iface_short_display: dict[str, str] = {}
        self.mac_var = tk.StringVar(value="")
        self.adapter_mac_var = tk.StringVar(value="")  # selected adapter's MAC, shown next to the combo -- see _refresh_adapters
        self.monitor_status_var = tk.StringVar(value="MONITOR: OFF")
        self.channel_lock_var = tk.StringVar(value="Scanning all channels")
        self.wordlist_var = tk.StringVar(value=self.settings.get("wordlist", ""))
        self.john_rules_var = tk.StringVar(value=self.settings.get("john_rules", ""))
        self.capture_dir_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")
        self.randomize_mac_var = tk.BooleanVar(value=self.settings.get("randomize_mac", True))

        from ..storage import capture_root

        self.capture_dir_var.set(self.settings.get("capture_dir") or str(capture_root()))

        self._build_menubar()
        self._build_toolbar()
        # Outline separating the toolbar from the body below it (2026-08-27
        # user report: "top bar needs an outline separating bar from window").
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X)
        self._build_body()
        self._build_status_bar()

        self._sort_col = self.settings.get("sort_col")
        self._sort_reverse = self.settings.get("sort_reverse", False)
        self.security_filter_var.set(self.settings.get("security_filter", "All"))

        self._refresh_adapters()
        saved_adapter = self.settings.get("adapter")
        if saved_adapter and saved_adapter in self._iface_display_to_name.values():
            self.adapter_var.set(saved_adapter)
            self._sync_iface_display(self.adapter_var, self.adapter_display_var)

        self.root.after(100, self._drain_queue)
        self.root.after(5000, self._check_channel_lock)
        self.root.after(200, lambda: self._check_dependencies(startup=True))
        # Advisory only: perform the GitHub check off the Tk thread and keep
        # radio/startup behavior independent of network availability.
        threading.Thread(target=self._check_for_updates, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if demo:
            self._load_demo_data()


def main(demo: bool = False) -> int:
    root = tk.Tk()
    App(root, demo=demo)
    root.mainloop()
    return 0
