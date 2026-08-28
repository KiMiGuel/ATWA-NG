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
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from .. import __version__
from ..scan import AccessPoint
from . import theme as theme_mod
from .crack_dialog import CrackDialog
from .widgets import SignalGraph

if TYPE_CHECKING:
    from .attack_runner import AttackRunner

BROADCAST = "ff:ff:ff:ff:ff:ff"

TARGET_COLUMNS = (
    ("bssid", "BSSID", 165),
    ("ssid", "SSID", 180),
    ("channel", "CH", 45),
    ("security", "Security", 100),
    ("pmf", "PMF", 90),
    ("wps", "WPS", 75),
    ("signal", "Signal", 75),
)

CAPTURE_COLUMNS = (
    ("name", "File", 220),
    ("kind", "Kind", 90),
    ("size", "Size", 80),
    ("path", "Path", 420),
)

# Channel-lock discipline: selecting a target auto-locks the adapter to
# that target's channel so a background scan loop doesn't keep hopping
# away from it mid-attack; auto-unlock after this many seconds of the
# locked target going unseen, so a stale lock doesn't strand the radio
# on a dead channel forever.
CHANNEL_LOCK_TIMEOUT = 30.0


class App:
    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.root.title(f"ATWA-NG — {__version__}")
        # Default to 1320x780, but never larger than the actual screen and
        # centered on it -- a hardcoded size bigger than the display (small
        # laptops, netbooks, anyone without a full-HD-or-larger monitor)
        # opened off-screen/clipped on first launch.
        screen_w, screen_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        win_w, win_h = min(1380, int(screen_w * 0.95)), min(780, int(screen_h * 0.88))
        self.root.geometry(f"{win_w}x{win_h}+{(screen_w - win_w) // 2}+{(screen_h - win_h) // 2}")
        self.root.minsize(min(760, win_w), min(480, win_h))
        self._set_window_icon()

        self.fonts = theme_mod.apply(root)
        self.THEME = theme_mod.THEME
        # White outline around the whole window (v1 reference look) -- Tk's
        # highlight ring is the only way to get a colored border on a
        # top-level window itself, as opposed to individual widgets.
        self.root.configure(highlightthickness=2, highlightbackground=self.THEME["border"],
                             highlightcolor=self.THEME["border"])

        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._scanning = threading.Event()
        self._stop_event = threading.Event()
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
        self._lock_capture_proc = None  # lock_capture.LockCapture | None
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
        self.monitor_status_var = tk.StringVar(value="MONITOR: OFF")
        self.channel_lock_var = tk.StringVar(value="Scanning all channels")
        self.wordlist_var = tk.StringVar(value=self.settings.get("wordlist", ""))
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
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if demo:
            self._load_demo_data()

    def _build_toolbar_logo(self, row1):
        """Logo mark in the toolbar's empty right-hand strip (2026-08-27
        user report: unused black space, "put that logo... as a button").
        Doubles as an About-dialog shortcut. Best-effort -- a missing/
        unreadable asset shouldn't block the toolbar from finishing."""
        assets = Path(__file__).parent / "assets"
        try:
            self._logo_image = tk.PhotoImage(file=str(assets / "logo_toolbar.png"))
        except tk.TclError:
            return
        # Accent-colored outline + hover highlight so it reads as clickable
        # and actually stands out against the toolbar (2026-08-27 user
        # report: "looks perfect except make it more noticeable").
        logo = tk.Label(
            row1, image=self._logo_image, bg=self.THEME["panel"], cursor="hand2",
            highlightthickness=2, highlightbackground=self.THEME["border"], highlightcolor=self.THEME["border"],
        )
        logo.pack(side=tk.RIGHT, padx=6)
        logo.bind("<Button-1>", lambda _e: self._show_about())
        logo.bind("<Enter>", lambda _e: logo.configure(bg=self.THEME["border"]))
        logo.bind("<Leave>", lambda _e: logo.configure(bg=self.THEME["panel"]))

    def _set_window_icon(self):
        """Window/taskbar icon from the approved logo mark. Best-effort --
        a missing/unreadable asset shouldn't block the GUI from launching."""
        assets = Path(__file__).parent / "assets"
        try:
            images = [tk.PhotoImage(file=str(assets / f"icon_{size}.png")) for size in (16, 32, 64, 128, 256)]
        except tk.TclError:
            return
        self._icon_images = images  # keep references -- Tk drops unreferenced PhotoImages
        self.root.iconphoto(True, *images)

    # ------------------------------------------------------------------
    # Menu bar — the resize-clip fix. Native window chrome, always reachable.
    # ------------------------------------------------------------------
    def _build_menubar(self):
        menubar = tk.Menu(self.root, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])

        file_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        file_menu.add_command(label="Set Capture Folder...", command=self._choose_capture_dir)
        file_menu.add_command(label="Set Wordlist...", command=self._choose_wordlist)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        scan_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        scan_menu.add_command(label="Refresh Adapters", command=self._refresh_adapters)
        scan_menu.add_command(label="Start Monitor Mode", command=self._start_monitor)
        scan_menu.add_command(label="Stop Monitor Mode", command=self._stop_monitor)
        scan_menu.add_checkbutton(label="Randomize MAC on Monitor Mode", variable=self.randomize_mac_var)
        scan_menu.add_separator()
        scan_menu.add_command(label="Start Scanning", command=self._start_scan)
        scan_menu.add_command(label="Stop Scanning", command=self._stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Unlock Channel (resume hopping)", command=self._unlock_channel)
        scan_menu.add_command(label="WPS Scan...", command=self._open_wps_scan)
        menubar.add_cascade(label="Scan", menu=scan_menu)

        attack_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        attack_menu.add_command(label="Deauth All Clients", command=self._attack_deauth_all)
        attack_menu.add_command(label="Deauth Selected Client", command=self._attack_deauth_client)
        attack_menu.add_command(label="PMKID Attack (Clientless)", command=self._attack_pmkid)
        attack_menu.add_command(label="Handshake Capture", command=self._attack_handshake)
        attack_menu.add_separator()
        attack_menu.add_command(label="Smart Attack (Auto)", command=self._attack_smart)
        attack_menu.add_command(label="OMNI Attack (All Stages)", command=self._attack_omni)
        attack_menu.add_command(label="WEP Attack", command=self._attack_wep)
        attack_menu.add_command(label="WEP Caffe Latte (client)", command=self._attack_caffe_latte)
        attack_menu.add_command(label="WEP Chopchop (decrypt)", command=self._attack_chopchop)
        attack_menu.add_command(label="WPS Null-PIN", command=self._attack_wps_null_pin)
        attack_menu.add_command(label="WPS Pixie-Dust (offline)", command=self._attack_wps_pixie)
        attack_menu.add_command(label="WPS Bruteforce (experimental)", command=self._attack_wps_bruteforce)
        attack_menu.add_command(label="Evil Twin (Captive Portal)", command=self._attack_eviltwin)
        attack_menu.add_command(label="Online Password Guess (live, budgeted)", command=self._attack_online_guess)
        attack_menu.add_separator()
        attack_menu.add_command(
            label="⚡ PINCER (Dual-Alfa)", command=self._attack_pincer, state=tk.DISABLED,
        )
        self.pincer_menu_index = attack_menu.index(tk.END)
        attack_menu.add_separator()
        attack_menu.add_command(label="Stop Attack", command=self._stop_attack)
        menubar.add_cascade(label="Attack", menu=attack_menu)
        self.attack_menu = attack_menu

        cap_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        cap_menu.add_command(label="Refresh Captures", command=self._refresh_captures)
        cap_menu.add_command(label="Inspect Selected", command=self._capture_inspect)
        cap_menu.add_command(label="Convert to 22000", command=self._capture_convert)
        cap_menu.add_command(label="Fix Capture", command=self._capture_fix)
        cap_menu.add_command(label="Merge Selected", command=self._capture_merge)
        cap_menu.add_command(label="Crack Selected", command=self._capture_crack)
        cap_menu.add_command(label="Copy Path", command=self._capture_copy_path)
        cap_menu.add_separator()
        cap_menu.add_command(label="Crack Handshakes (folder)...", command=self._open_crack_dialog)
        cap_menu.add_command(label="Cleanup Handshakes...", command=self._capture_cleanup)
        menubar.add_cascade(label="Captures", menu=cap_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        help_menu.add_command(label="Check Dependencies", command=self._check_dependencies)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        # Plain tagline text after Help, not a real cascade -- state=DISABLED
        # keeps it non-clickable. Leading spaces push it rightward (native
        # tk.Menu has no pack/place-style alignment option, so padding the
        # label is the standard workaround) -- 2026-08-27 user request.
        menubar.add_command(label=" " * 40 + "Airwave Teardown Wireless Auditing-NG", state=tk.DISABLED)

        self.root.config(menu=menubar)

    # ------------------------------------------------------------------
    # Toolbar — deliberately minimal (few widgets => unlikely to overflow
    # even on its own), authoritative access stays in the menu bar above.
    # ------------------------------------------------------------------
    def _build_toolbar(self):
        # Two short rows rather than one long one: each row alone is far
        # below the width where wrapping/clipping would ever kick in, and
        # the menu bar above duplicates every action here regardless.
        container = ttk.Frame(self.root, style="Toolbar.TFrame", padding=4)
        container.pack(side=tk.TOP, fill=tk.X)

        row1 = ttk.Frame(container, style="Toolbar.TFrame")
        row1.pack(side=tk.TOP, fill=tk.X)

        # Adapter/AP iface stacked in their own column (AP iface directly
        # under Adapter, per user request) -- keeps the two interface
        # pickers grouped and visually paired instead of strung out along
        # one long row with the action buttons.
        iface_col = ttk.Frame(row1, style="Toolbar.TFrame")
        iface_col.pack(side=tk.LEFT, padx=(2, 10))
        ttk.Label(iface_col, text="Adapter:", style="Toolbar.TLabel").grid(row=0, column=0, sticky=tk.W)
        # Chipset/vendor shown inside the dropdown itself ("wlan1
        # (Mediatek)"), not as a separate always-on label (2026-08-27 user
        # report, v1 reference has no such label) -- adapter_var still holds
        # just the bare iface name for every downstream radio call.
        self.adapter_combo = ttk.Combobox(iface_col, textvariable=self.adapter_display_var, state="readonly", width=20)
        self.adapter_combo.grid(row=0, column=1, padx=(4, 0))
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_adapter_selected())
        ttk.Label(iface_col, text="AP iface:", style="Toolbar.TLabel").grid(row=1, column=0, sticky=tk.W, pady=(2, 0))
        self.iface_ap_combo = ttk.Combobox(iface_col, textvariable=self.iface_ap_display_var, state="readonly", width=20)
        self.iface_ap_combo.grid(row=1, column=1, padx=(4, 0), pady=(2, 0))
        self.iface_ap_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_iface_ap_selected())

        # MAC now shown in the Adapter dropdown itself (_iface_display),
        # not a separate label here (2026-08-27 user request).
        # Start Scanning / Stop Scan are two static buttons, not one
        # toggling button, matching Start/Stop Monitor's pattern -- order
        # per user request: Start Scanning, Stop Scan, Start Monitor,
        # Stop Monitor, WPS Scan, Unlock.
        self.scan_btn = ttk.Button(row1, text="Start Scanning", command=self._start_scan, style="Toolbar.Accent.TButton")
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(row1, text="Stop Scan", command=self._stop_scan, style="Toolbar.TButton").pack(
            side=tk.LEFT, padx=4)
        ttk.Button(row1, text="Start Monitor", command=self._start_monitor, style="Toolbar.TButton").pack(
            side=tk.LEFT, padx=4)
        ttk.Button(row1, text="Stop Monitor", command=self._stop_monitor, style="Toolbar.TButton").pack(
            side=tk.LEFT, padx=4)
        ttk.Button(row1, text="WPS Scan", command=self._open_wps_scan, style="Toolbar.TButton").pack(
            side=tk.LEFT, padx=4)
        ttk.Button(row1, text="Unlock", command=self._unlock_channel, style="Toolbar.TButton").pack(
            side=tk.LEFT, padx=4)
        self._build_toolbar_logo(row1)
        # No toolbar monitor-status pill (removed per 2026-08-27 user
        # report -- monitor state still logs via _run_bg's own start/result
        # lines and the status bar, just not as a standing toolbar widget).

    # ------------------------------------------------------------------
    # Body: PanedWindow(target tree | single scrolling target/captures pane) + log
    # ------------------------------------------------------------------
    def _make_scrollable(self, parent) -> ttk.Frame:
        """Canvas+Scrollbar wrapper — the Target tab's content (signal
        graph + 10 attack buttons + auto-deauth row) is taller than fits
        on a shorter window with no scroll path otherwise; real bug user
        hit ("WPS Null-PIN barely visible", buttons below it unreachable).
        Returns the inner frame to build content into."""
        canvas = tk.Canvas(parent, bg=self.THEME["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor=tk.NW)

        def on_inner_configure(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event):
            canvas.itemconfig(window, width=event.width)

        inner.bind("<Configure>", on_inner_configure)
        canvas.bind("<Configure>", on_canvas_configure)

        def on_wheel(event):
            # event.num is set for X11's native Button-4/5 wheel events
            # (event.delta is 0 on those); event.delta is set for the
            # Windows/Mac-style MouseWheel event. Handle whichever this
            # Tk build actually delivers rather than assuming one.
            if event.num == 5 or event.delta < 0:
                canvas.yview_scroll(1, "units")
            elif event.num == 4 or event.delta > 0:
                canvas.yview_scroll(-1, "units")

        # Enter/Leave bound on the bare canvas only used to mean scrolling
        # worked while hovering the canvas's own background pixels -- but
        # `inner` (and everything packed into it: Target/Clients/graph/
        # Attacks/Captures) sits ON TOP of the canvas covering nearly all
        # of it, so the pointer left "the canvas" the instant it crossed
        # onto any actual content, unbinding wheel scroll almost
        # everywhere (2026-08-27 user report: scroll wasn't working on
        # the right side). Bind directly on every descendant instead, once
        # they all exist -- see _bind_wheel_recursive, called after this
        # pane's content is built.
        self._wheel_bind_target = (canvas, on_wheel)
        return inner

    def _bind_wheel_recursive(self, widget, on_wheel, skip=frozenset()):
        """skip: widgets whose own subtree gets a dedicated scroller
        instead (e.g. the Captures list, which needs to scroll itself,
        not the outer page -- 2026-08-27 user report)."""
        if widget in skip:
            return
        widget.bind("<MouseWheel>", on_wheel, add="+")
        widget.bind("<Button-4>", on_wheel, add="+")
        widget.bind("<Button-5>", on_wheel, add="+")
        for child in widget.winfo_children():
            self._bind_wheel_recursive(child, on_wheel, skip)

    def _build_body(self):
        # Single scrolling right-hand pane, no tabs (2026-08-27 reskin toward
        # v1's dense layout) -- Target details, signal graph, Clients, Attacks,
        # and Captures all stack in one column instead of splitting Target/
        # Captures across notebook tabs, which cost a click and vertical
        # space for the tab strip itself.
        body = ttk.Frame(self.root, padding=2)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        pane = ttk.PanedWindow(body, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body)
        pane.add(left, weight=2)
        self._build_target_tree(left)

        right = ttk.Frame(body)
        pane.add(right, weight=3)
        inner = self._make_scrollable(right)
        self._build_target_panel(inner)
        canvas, on_wheel = self._wheel_bind_target
        self._bind_wheel_recursive(inner, on_wheel, skip={self.captures_box})
        self._bind_wheel_recursive(canvas, on_wheel)

        # Log stays a full-width bottom strip, always visible (user
        # live-test note 2026-08-27: moving it into a notebook tab hid it).
        self._build_log_pane(body)

    def _build_target_tree(self, outer_parent):
        # Boxed like every other section (Target/Clients/Attacks/Captures) --
        # this was the one panel left as a bare frame with no border, which
        # read as visually inconsistent (2026-08-27 user report: "needs more
        # outlines to look visually organized").
        # "Scanned Access Points" moved off the box border into this row,
        # right next to Filter (2026-08-27 user request) -- the LabelFrame
        # itself stays untitled, just the bordered outline.
        box = ttk.Frame(outer_parent, style="Bordered.TFrame")
        box.pack(fill=tk.BOTH, expand=True)
        parent = ttk.Frame(box)
        parent.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        filter_row = ttk.Frame(parent)
        filter_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(filter_row, text="Scanned Access Points", style="Heading.TLabel").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(filter_row, text="Filter:").pack(side=tk.LEFT)
        self.security_filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(
            filter_row, textvariable=self.security_filter_var, state="readonly", width=14,
            values=("All", "Open", "WEP", "WPA/WPA2", "WPA3", "Transition"),
        )
        filter_combo.pack(side=tk.LEFT, padx=6)
        filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_targets())
        # MAC moved here (2026-08-27 user request): ttk.Combobox's popdown
        # list width tracks the widget's own configured width, not its
        # longest value, so the MAC-suffixed dropdown entries were getting
        # clipped the same as the closed field -- a real ttk limitation,
        # not fixable by a wider string. Plain text next to Filter instead.
        ttk.Label(filter_row, textvariable=self.mac_var, style="Muted.TLabel").pack(side=tk.LEFT, padx=(12, 0))

        # Separator between the filter controls and the results list
        # (2026-08-27 user report: "the scan window needs separator lines").
        ttk.Separator(parent, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 4))

        # Horizontal scrollbar packed into parent BEFORE tree_frame so it
        # claims its strip at the bottom first — packing it after would
        # leave it no space once tree_frame's fill=BOTH/expand=True already
        # claimed everything.
        hsb = ttk.Scrollbar(parent, orient=tk.HORIZONTAL)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = [c[0] for c in TARGET_COLUMNS]
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for key, heading, width in TARGET_COLUMNS:
            self.tree.heading(key, text=heading, command=lambda c=key: self._on_target_heading_click(c))
            # stretch=False: columns keep whatever width the user drags them
            # to instead of ttk auto-compressing them to fit the visible
            # pane — needed for the horizontal scrollbar below to mean
            # anything (2026-08-26 live-test note: columns weren't
            # comfortably resizable/reachable when narrower than total width).
            self.tree.column(key, width=width, minwidth=40, stretch=False)
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb.configure(command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._on_target_select)
        self.tree.bind("<Double-1>", self._on_target_double_click)
        self.tree.bind("<Button-3>", self._on_target_right_click)

        # Wheel scroll over the whole box (Filter row, empty tree area),
        # not just rows with content -- same reasoning as the right-side
        # fix above (2026-08-27 user report: scroll wasn't reliable on
        # either side).
        def on_tree_wheel(event):
            if event.num == 5 or event.delta < 0:
                self.tree.yview_scroll(1, "units")
            elif event.num == 4 or event.delta > 0:
                self.tree.yview_scroll(-1, "units")
        self._bind_wheel_recursive(box, on_tree_wheel)

        self.hidden_columns: set[str] = set(self.settings.get("hidden_columns", []))
        self._apply_column_visibility()

        # Row color by security (OPN/WEP/WPA/WPA2/WPA3).
        self.tree.tag_configure("open", foreground=self.THEME["go"])
        self.tree.tag_configure("wep", foreground=self.THEME["error"])
        self.tree.tag_configure("wpa", foreground=self.THEME["warn"])
        self.tree.tag_configure("wpa2", foreground="#ffffff")
        self.tree.tag_configure("wpa3", foreground=self.THEME["info"])
        self.tree.tag_configure("transition", foreground="#cc88ff")
        self.tree.tag_configure("unknown", foreground=self.THEME["muted"])

        # Subtle row banding so the target list reads as separated rows
        # instead of one bunched block of text (2026-08-24 live-test note) —
        # ttk.Treeview under "clam" has no simple per-cell gridline option,
        # so alternating row background is the practical equivalent.
        # 2026-08-27: moved to the lighter tree_bg/tree_band tokens so the
        # list surface itself is visible against the window background.
        self.tree.tag_configure("row_even", background=self.THEME["tree_bg"])
        self.tree.tag_configure("row_odd", background=self.THEME["tree_band"])

        self._sort_col: str | None = None
        self._sort_reverse = False

    def _build_target_panel(self, parent):
        # Single column, bordered sections stacked top-to-bottom (2026-08-27
        # reskin: v1's dense layout, no side-by-side split) -- parent is
        # already a scrolling canvas (_make_scrollable), so there's no fixed
        # height to budget for the way the old tabbed/two-column layout had to.
        # Title and controls on separate rows: an unbounded-length SSID (up
        # to 32 bytes) sharing a row with the lock pill/Unlock/Stop Attack
        # buttons squeezed them together/overlapped (regression caught via
        # screenshot during the 2026-08-27 reskin -- same issue this layout
        # had before, when it was fixed by splitting these into two rows).
        title_row = ttk.Frame(parent)
        title_row.pack(fill=tk.X)
        self.target_title_var = tk.StringVar(value="No target selected")
        ttk.Label(title_row, textvariable=self.target_title_var, style="Heading.TLabel").pack(side=tk.LEFT)

        # Target box: one field per line (v1 reference: "look how much info
        # is on the target window" -- ESSID/BSSID's separate outer heading
        # above still covers those two, so this focuses on everything else).
        # Lock status is a plain color-coded line here, not a separate
        # filled pill (2026-08-27 user report, same reasoning as the
        # toolbar's monitor-status pill removal).
        target_box = ttk.LabelFrame(parent, text="Target")
        target_box.pack(fill=tk.X, pady=(4, 4))
        self.lock_status_label = tk.Label(
            target_box, textvariable=self.channel_lock_var, bg=self.THEME["bg"], fg=self.THEME["error"],
            font=self.fonts["ui_bold"], anchor=tk.W,
        )
        self.lock_status_label.pack(fill=tk.X, padx=6, pady=(4, 0))
        self.target_detail_var = tk.StringVar(value="Select a target from the list on the left.")
        ttk.Label(target_box, textvariable=self.target_detail_var, justify=tk.LEFT).pack(
            anchor=tk.W, padx=6, pady=(2, 0))
        self.capture_size_var = tk.StringVar(value="")
        ttk.Label(target_box, textvariable=self.capture_size_var, style="Muted.TLabel").pack(
            anchor=tk.W, padx=6, pady=(0, 4))

        clients_box = ttk.LabelFrame(parent, text="Clients")
        clients_box.pack(fill=tk.X, pady=(0, 4))
        client_frame = ttk.Frame(clients_box)
        client_frame.pack(fill=tk.X, padx=4, pady=4)
        self.client_tree = ttk.Treeview(
            client_frame, columns=("station", "signal"), show="headings", height=3, selectmode="browse",
        )
        self.client_tree.heading("station", text="Station")
        self.client_tree.column("station", width=160, minwidth=120)
        self.client_tree.heading("signal", text="Signal")
        self.client_tree.column("signal", width=70, minwidth=50)
        self.client_tree.tag_configure("row_even", background=self.THEME["tree_bg"])
        self.client_tree.tag_configure("row_odd", background=self.THEME["tree_band"])
        self.client_tree.bind("<Button-3>", self._on_client_right_click)
        client_vsb = ttk.Scrollbar(client_frame, orient=tk.VERTICAL, command=self.client_tree.yview)
        self.client_tree.configure(yscrollcommand=client_vsb.set)
        self.client_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        client_vsb.pack(side=tk.LEFT, fill=tk.Y)

        # Boxed like Target/Clients/Attacks/Captures -- this was the one
        # right-side element with no border at all (2026-08-27 user
        # report: "the right side... needs more outlines").
        graph_box = ttk.LabelFrame(parent, text="Signal History")
        graph_box.pack(fill=tk.X, pady=(0, 4))
        graph_frame = ttk.Frame(graph_box, style="Panel.TFrame")
        graph_frame.pack(fill=tk.X, padx=4, pady=4)
        self.signal_graph = SignalGraph(graph_frame)

        auto_row = ttk.Frame(parent)
        auto_row.pack(fill=tk.X, pady=(0, 4))
        self.auto_deauth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_row, text="Auto-deauth until handshake", variable=self.auto_deauth_var,
                        command=self._toggle_auto_deauth).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="every").pack(side=tk.LEFT, padx=(10, 4))
        self.deauth_interval_var = tk.StringVar(value="10")
        ttk.Combobox(auto_row, textvariable=self.deauth_interval_var, state="readonly", width=4,
                     values=("10", "30", "60")).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="s").pack(side=tk.LEFT, padx=(2, 0))

        attacks_box = ttk.LabelFrame(parent, text="Attacks")
        attacks_box.pack(fill=tk.X, pady=(0, 4))
        # Stop Attack pinned at the top of the list, not mixed into
        # self.attack_buttons below -- it must stay clickable while
        # _set_busy(True) disables every other attack button, since its
        # whole job is interrupting one that's already running.
        ttk.Button(attacks_box, text="Stop Attack", command=self._stop_attack, style="Danger.TButton").pack(
            fill=tk.X, padx=4, pady=(4, 4))
        buttons = [
            ("Deauth All Clients", self._attack_deauth_all, "TButton"),
            ("Deauth Selected Client", self._attack_deauth_client, "TButton"),
            ("PMKID Attack (Clientless)", self._attack_pmkid, "TButton"),
            ("Handshake Capture", self._attack_handshake, "TButton"),
            ("Smart Attack (Auto)", self._attack_smart, "Accent.TButton"),
            ("OMNI Attack (All Stages)", self._attack_omni, "Accent.TButton"),
            ("WEP Attack", self._attack_wep, "TButton"),
            ("WEP Caffe Latte", self._attack_caffe_latte, "TButton"),
            ("WEP Chopchop", self._attack_chopchop, "TButton"),
            ("WPS Null-PIN", self._attack_wps_null_pin, "TButton"),
            ("WPS Pixie-Dust", self._attack_wps_pixie, "TButton"),
            ("WPS Bruteforce (experimental)", self._attack_wps_bruteforce, "TButton"),
            ("Evil Twin (Captive Portal)", self._attack_eviltwin, "TButton"),
            ("Online Password Guess", self._attack_online_guess, "TButton"),
        ]
        self.attack_buttons: list[ttk.Button] = []
        for label, cmd, style in buttons:
            b = ttk.Button(attacks_box, text=label, command=cmd, style=style)
            b.pack(fill=tk.X, padx=4, pady=1)
            self.attack_buttons.append(b)

        # PINCER kept out of self.attack_buttons: it needs a second enable
        # condition (a detected dual-Alfa pair) that _set_busy()'s blanket
        # NORMAL-on-idle reset would otherwise clobber -- see _set_busy()
        # and _refresh_adapters() for where its state actually gets set.
        self.pincer_button = ttk.Button(
            attacks_box, text="⚡ PINCER (Dual-Alfa)", command=self._attack_pincer, state=tk.DISABLED,
        )
        self.pincer_button.pack(fill=tk.X, padx=4, pady=1)

        self.captures_box = ttk.LabelFrame(parent, text="Captures")
        self.captures_box.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self._build_captures_panel(self.captures_box)

    def _build_captures_panel(self, parent):
        opts_row = ttk.Frame(parent)
        opts_row.pack(fill=tk.X, padx=4, pady=(4, 6))
        ttk.Label(opts_row, text="Capture dir:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.capture_dir_var, width=40).grid(row=0, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_capture_dir).grid(row=0, column=2)
        ttk.Label(opts_row, text="Wordlist:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.wordlist_var, width=40).grid(row=1, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_wordlist).grid(row=1, column=2)
        opts_row.columnconfigure(1, weight=1)

        actions = ttk.Frame(parent)
        actions.pack(fill=tk.X, padx=4, pady=(0, 4))
        for label, cmd in (
            ("Refresh", self._refresh_captures),
            ("Inspect", self._capture_inspect),
            ("Convert to 22000", self._capture_convert),
            ("Fix", self._capture_fix),
            ("Merge (2+)", self._capture_merge),
            ("Crack Selected", self._capture_crack),
            ("Copy Path", self._capture_copy_path),
        ):
            ttk.Button(actions, text=label, command=cmd).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions, text="Crack Handshakes (folder)...", command=self._open_crack_dialog,
                   style="Accent.TButton").pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(actions, text="Cleanup Handshakes...", command=self._capture_cleanup, style="Danger.TButton").pack(side=tk.LEFT, padx=2)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        cols = [c[0] for c in CAPTURE_COLUMNS]
        self.capture_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended", height=6)
        for key, heading, width in CAPTURE_COLUMNS:
            self.capture_tree.heading(key, text=heading)
            self.capture_tree.column(key, width=width, minwidth=40)
        self.capture_tree.tag_configure("row_even", background=self.THEME["tree_bg"])
        self.capture_tree.tag_configure("row_odd", background=self.THEME["tree_band"])
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.capture_tree.yview)
        self.capture_tree.configure(yscrollcommand=vsb.set)
        self.capture_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.capture_tree.bind("<Button-3>", self._on_capture_right_click)

        # Own dedicated scroll, not the outer page's (2026-08-27 user
        # report: "the handshakes box needs its own scroll bars") --
        # excluded from the outer canvas's recursive wheel-bind via
        # skip={self.captures_box} in _build_body().
        def on_capture_wheel(event):
            if event.num == 5 or event.delta < 0:
                self.capture_tree.yview_scroll(1, "units")
            elif event.num == 4 or event.delta > 0:
                self.capture_tree.yview_scroll(-1, "units")
        self._bind_wheel_recursive(parent, on_capture_wheel)

        self.root.after(50, self._refresh_captures)

    def _build_log_pane(self, parent):
        # Full-width bottom strip, always visible during attacks.
        frame = ttk.Frame(parent)
        frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))
        ttk.Label(frame, text="Log", style="Muted.TLabel").pack(anchor=tk.W)
        self.log_text = tk.Text(
            frame, height=8, bg=self.THEME["panel_alt"], fg=self.THEME["fg"], insertbackground=self.THEME["fg"],
            font=self.fonts["mono"], borderwidth=0, highlightthickness=1,
            highlightbackground=self.THEME["border"], wrap=tk.WORD,
        )
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set, state=tk.DISABLED)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.LEFT, fill=tk.Y)

    def _build_status_bar(self):
        bar = ttk.Frame(self.root, style="Status.TFrame", padding=(8, 3))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(bar, textvariable=self.status_var, style="Toolbar.TLabel").pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Background execution: run fn() off the UI thread, results/log lines
    # come back through a queue drained on the Tk main loop via `after`.
    # ------------------------------------------------------------------
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "scan_update":
                    self._render_targets()
                elif kind == "signal_sample":
                    self.signal_graph.add_sample(payload)
                elif kind == "auto_deauth_done":
                    self.auto_deauth_var.set(False)
                elif kind == "capture_size":
                    self.capture_size_var.set(self._format_capture_size(payload))
                elif kind == "busy":
                    self._set_busy(payload)
                elif kind == "error":
                    messagebox.showerror("ATWA-NG", payload)
                elif kind == "info":
                    messagebox.showinfo("ATWA-NG", payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _append_log(self, msg: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg.rstrip() + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _log(self, msg: str):
        self._queue.put(("log", msg))

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for b in self.attack_buttons:
            b.configure(state=state)
        self.pincer_button.configure(state=tk.DISABLED if (busy or not self.alfa_pair) else tk.NORMAL)

    def _runner(self) -> AttackRunner:
        """Build an AttackRunner from current App state."""
        from .attack_runner import AttackRunner

        return AttackRunner(
            mon_iface=self.mon_iface,
            own_mac=self.own_mac,
            capture_dir=self.capture_dir_var.get(),
            wordlist=self.wordlist_var.get() or None,
            stop_event=self._stop_event,
            progress_fn=self._progress_fn,
            log_fn=self._log,
            watch_capture_fn=self._watch_capture_size,
        )

    def _run_bg(self, label: str, fn, *args, **kwargs):
        """Run fn(*args, **kwargs) in a background thread; log start/result/
        error, plus a periodic heartbeat while it's running. User feedback
        (2026-08-20): with no output for up to 60s (PMKID/handshake/WEP
        timeouts), it wasn't visible anything was actually happening.
        Generic fix at this one choke point instead of threading progress
        callbacks through every individual attack function."""
        if self._busy:
            messagebox.showwarning("ATWA-NG", "Another attack is already running. Use Stop Attack first.")
            return
        # A prior attack's "Stop Attack" leaves this set; without clearing
        # it here, every later attack that reads self._stop_event (Caffe
        # Latte, Chopchop, Evil Twin, Handshake Capture) would see itself
        # as already-stopped and abort instantly.
        self._stop_event.clear()
        self._queue.put(("busy", True))
        self._queue.put(("status", f"Running: {label}"))
        self._log(f">>> {label}")
        # Cheap, high-value sanity check: an attack that silently no-ops
        # because mon_iface slipped out of monitor mode (a stuck driver
        # state, a stray NetworkManager reclaim, etc.) looks identical in
        # the log to "the attack ran and found nothing" without this —
        # the single most confusing failure mode to diagnose blind.
        if self.mon_iface and "demo" not in self.mon_iface:
            try:
                from ..radio import get_mode

                mode = get_mode(self.mon_iface)
                if mode != "monitor":
                    self._log(f"    WARNING: {self.mon_iface} needs to be in monitor mode but is currently in '{mode}' mode — {label} will likely fail silently")
                else:
                    self._log(f"    {self.mon_iface}: monitor mode confirmed")
            except Exception as exc:  # noqa: BLE001 - GUI must survive adapter-query errors
                self._log(f"    could not check {self.mon_iface} mode: {exc}")

        done = threading.Event()
        _last_progress: list[str] = []

        def progress_fn(msg: str) -> None:
            """Attack functions call this to emit mid-run status lines."""
            _last_progress.clear()
            _last_progress.append(msg)
            self._log(f"    {msg}")

        # Expose progress_fn to work functions via a thread-local attribute
        # so they can capture it without changing _run_bg's signature.
        self._progress_fn = progress_fn

        def heartbeat():
            elapsed = 0
            while not done.wait(10):
                elapsed += 10
                last = _last_progress[0] if _last_progress else None
                if last:
                    self._log(f"    [{elapsed}s] {last}")
                else:
                    self._log(f"    ... {label} still running ({elapsed}s)")

        threading.Thread(target=heartbeat, daemon=True).start()

        def worker():
            try:
                result = fn(*args, **kwargs)
                self._log(f"<<< {label} done: {result if result is not None else 'ok'}")
            except Exception as exc:  # noqa: BLE001 — surface every failure to the log/dialog
                self._log(f"!!! {label} failed: {exc}")
                self._queue.put(("error", f"{label} failed:\n{exc}"))
            finally:
                done.set()
                self._queue.put(("busy", False))
                self._queue.put(("status", "Ready."))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Adapters / monitor mode
    # ------------------------------------------------------------------
    def _refresh_adapters(self):
        from ..radio import detect_alfa_pair, detect_interfaces

        try:
            ifaces = detect_interfaces()
        except Exception as exc:  # noqa: BLE001 - GUI must survive adapter-query errors
            self._log(f"could not list adapters: {exc}")
            ifaces = []

        displays = [self._iface_display(i) for i in ifaces]
        self._iface_display_to_name = dict(zip(displays, ifaces))
        self._iface_short_display = {i: self._iface_display_short(i) for i in ifaces}
        self.adapter_combo["values"] = displays
        self.iface_ap_combo["values"] = displays

        if ifaces and not self.adapter_var.get():
            self.adapter_var.set(ifaces[0])
        self._sync_iface_display(self.adapter_var, self.adapter_display_var)

        saved_iface_ap = self.settings.get("iface_ap", "")
        if saved_iface_ap and saved_iface_ap in ifaces:
            self.iface_ap_var.set(saved_iface_ap)
        elif not self.iface_ap_var.get() or self.iface_ap_var.get() not in ifaces:
            # Evil Twin needs a *second* interface distinct from the
            # monitor/scan adapter to host the AP on — default to the
            # first one that isn't already selected as the scan adapter.
            others = [i for i in ifaces if i != self.adapter_var.get()]
            self.iface_ap_var.set((others or ifaces or [""])[0])
        self._sync_iface_display(self.iface_ap_var, self.iface_ap_display_var)

        self.alfa_pair = detect_alfa_pair(ifaces)
        state = tk.NORMAL if (self.alfa_pair and not self._busy) else tk.DISABLED
        if hasattr(self, "pincer_menu_index"):
            self.attack_menu.entryconfig(self.pincer_menu_index, state=state)
        if hasattr(self, "pincer_button"):
            self.pincer_button.configure(state=state)
        if self.alfa_pair:
            self._log(f"PINCER available: scan={self.alfa_pair[0]} attack={self.alfa_pair[1]}")

    def _sync_iface_display(self, name_var: tk.StringVar, display_var: tk.StringVar):
        """Point display_var at name_var's current bare iface name's SHORT
        display string (iface + vendor, no MAC -- the collapsed field is
        too narrow for the MAC too), falling back to the bare name itself
        if it's not in the current interface list (e.g. nothing detected
        yet). The dropdown *list* still shows the full iface+vendor+MAC
        form via combo["values"] (2026-08-27 user request)."""
        name = name_var.get()
        display_var.set(self._iface_short_display.get(name, name))

    @staticmethod
    def _display_ssid(ssid: str) -> str:
        """Render an SSID for the tree. Real, non-UTF8 SSIDs decode fine
        (frames.py falls back to latin-1 so nothing crashes), but many of
        those bytes are control/undefined codepoints that Tk renders as a
        wall of missing-glyph boxes. Swap only the non-printable characters
        for a single visible placeholder — display only, the underlying
        ap.ssid stays untouched for attacks/captures/targeting."""
        return "".join(c if c.isprintable() else "·" for c in ssid)

    @staticmethod
    def _vendor_label(driver: str | None) -> str:
        """Rough driver-name -> vendor label, purely so wlan0/wlan1 in the
        toolbar are visually distinguishable when both are present — not
        an exhaustive chipset database, just the common driver prefixes."""
        if not driver:
            return "?"
        d = driver.lower()
        if d.startswith("mt"):
            return "Mediatek"
        if d.startswith(("rtl", "rtw")):
            return "Realtek"
        if d.startswith("ath"):
            return "Atheros"
        if d.startswith("iwl"):
            return "Intel"
        return driver

    def _iface_display_short(self, iface: str) -> str:
        from ..radio import get_driver

        driver = get_driver(iface)
        return f"{iface} ({self._vendor_label(driver)})" if driver else iface

    def _iface_display(self, iface: str) -> str:
        """Full form for the dropdown list: iface + vendor + MAC. See
        _iface_display_short() for the collapsed-field form."""
        from ..radio import RadioError, get_mac

        parts = [self._iface_display_short(iface)]
        try:
            parts.append(get_mac(iface))
        except RadioError:
            pass  # interface down/gone between detect and here -- MAC just isn't shown
        return " ".join(parts)

    def _on_adapter_selected(self):
        self.adapter_var.set(self._iface_display_to_name.get(self.adapter_display_var.get(), self.adapter_display_var.get()))
        self._sync_iface_display(self.adapter_var, self.adapter_display_var)

    def _on_iface_ap_selected(self):
        self.iface_ap_var.set(self._iface_display_to_name.get(self.iface_ap_display_var.get(), self.iface_ap_display_var.get()))
        self._sync_iface_display(self.iface_ap_var, self.iface_ap_display_var)
        self._save_settings()

    def _start_monitor(self):
        iface = self.adapter_var.get()
        if not iface:
            messagebox.showwarning("ATWA-NG", "Select an adapter first.")
            return

        def work():
            from ..radio import get_mac, set_monitor_mode

            mon, permanent_mac = set_monitor_mode(iface, randomize_mac=self.randomize_mac_var.get())
            mac = get_mac(mon)
            self.mon_iface = mon
            self.own_mac = mac
            self._permanent_mac = permanent_mac
            self._queue.put(("status", f"Monitor mode on {mon}"))
            self.mac_var.set(mac + (" (randomized)" if permanent_mac else ""))
            self.monitor_status_var.set(f"MONITOR: {mon}")
            return mon

        self._run_bg("Start monitor mode", work)

    def _stop_monitor(self):
        if not self.mon_iface:
            return
        iface = self.mon_iface
        permanent_mac = self._permanent_mac

        def work():
            from ..radio import set_managed_mode

            set_managed_mode(iface, restore_mac=permanent_mac)
            self.mon_iface = None
            self._permanent_mac = None
            self.monitor_status_var.set("MONITOR: OFF")
            return iface

        self._run_bg("Stop monitor mode", work)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _start_scan(self):
        if not self.mon_iface:
            messagebox.showwarning("ATWA-NG", "Start monitor mode first.")
            return
        if self._scanning.is_set():
            return
        self._scanning.set()
        self._log("scanning started")

        def loop():
            import time

            from scapy.sendrecv import sniff

            from ..frames import bssid_of
            from ..radio import ALL_CHANNELS, ChannelHopper
            from ..scan import ScanResult, process_packet

            # One persistent hopper for the whole scanning session, not a
            # fresh one per pass — matches how the compiled scan engine actually works
            # (confirmed via --help: one continuous hop loop, incremental
            # display, never restarts). The old design called scan() in a
            # loop, which builds a brand-new ChannelHopper every time — its
            # channel index always restarted at 0, so with hop() costing a
            # full dwell itself (0.3s) *plus* the 0.3s sniff (0.6s/channel,
            # 13.2s for a full 22-channel sweep), a short bounded duration
            # never reached 5GHz at all, not just less often. process_packet
            # already merges correctly into a persistent ScanResult (fixed
            # 2026-08-19), so this also drops the GUI's own duplicate merge
            # logic that used to sit here.
            result = ScanResult(aps=self.aps)
            hopper = ChannelHopper(iface=self.mon_iface, channels=self._scan_channels or list(ALL_CHANNELS))

            def on_packet(pkt):
                bssid = bssid_of(pkt)
                had_ssid = result.aps[bssid].ssid if bssid in result.aps else None
                process_packet(pkt, result)
                if bssid and bssid in result.aps and not had_ssid and result.aps[bssid].ssid:
                    self._log(f"revealed hidden SSID: {result.aps[bssid].ssid} ({bssid})")

            while self._scanning.is_set():
                # An attack (deauth/capture/PMKID/WPS/PINCER/auto-deauth)
                # needs exclusive use of mon_iface. Without this check the
                # scan loop kept opening/closing its own sniff() socket on
                # the same interface every dwell period even while an
                # attack was running, which starved both TX (deauth frames
                # never actually went out — confirmed via `ip -s link`
                # showing 0 TX packets) and RX (capture files came back
                # with 0 packets) and occasionally raised a real ENETDOWN
                # from the resulting socket churn. Pause hopping/sniffing
                # entirely while busy instead of fighting over the radio.
                if self._busy:
                    time.sleep(0.3)
                    continue
                # Locked/unlocked can change mid-session (double-click a
                # different target, hit Unlock) — pick that up each hop
                # rather than only at loop start.
                wanted = self._scan_channels or list(ALL_CHANNELS)
                if hopper.channels != wanted:
                    hopper.channels = wanted
                hopper.hop()
                try:
                    sniff(iface=self.mon_iface, timeout=hopper.dwell, prn=on_packet, store=False)
                except Exception as exc:  # noqa: BLE001 - transient driver errors during hop must not kill scan
                    # Transient: some drivers (e.g. mt76x0u) briefly drop the
                    # link during a fast 2.4->5GHz channel hop, which makes
                    # scapy's L2 socket setup fail for that one dwell window
                    # (observed live: "[Errno 100] Network is down"). Treating
                    # that as fatal silently killed the whole scan session —
                    # button still said "Stop Scanning" but nothing was being
                    # captured, which reads as "this adapter just sees fewer
                    # APs" rather than "the scan died a few seconds in".
                    self._log(f"scan hop failed, retrying: {exc}")
                    time.sleep(0.5)
                    continue
                if self.locked_bssid and self.locked_bssid in result.aps:
                    self._lock_lost_since = None
                # Signal graph follows whatever's SELECTED, not just locked
                # (2026-08-26 live-test note: single-click a row should
                # immediately start updating the graph, not just after a
                # double-click lock — selected_bssid equals locked_bssid
                # once you do lock, since selection fires with the click).
                if self.selected_bssid and self.selected_bssid in result.aps:
                    # last_signal, not signal -- signal is a running best-ever
                    # max (by design, for the target list/sort column), which
                    # ratchets up once and then plateaus forever. Feeding that
                    # into a rolling time graph made it look permanently stuck
                    # after the first strong reading instead of tracking the
                    # actual live RSSI.
                    self._queue.put(("signal_sample", result.aps[self.selected_bssid].last_signal))
                self._queue.put(("scan_update", None))

        self._scan_thread = threading.Thread(target=loop, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        self._scanning.clear()
        self._log("scanning stopped")

    def _matches_security_filter(self, ap: AccessPoint) -> bool:
        filt = self.security_filter_var.get()
        sec = (ap.security or "").lower()
        if filt == "All":
            return True
        if filt == "Open":
            return sec == "open"
        if filt == "WEP":
            return sec == "wep"
        if filt == "WPA/WPA2":
            return sec in ("wpa", "wpa2")
        if filt == "WPA3":
            return sec == "wpa3"
        if filt == "Transition":
            return sec == "transition"
        return True

    def _render_targets(self):
        selected = self.selected_bssid
        self.tree.delete(*self.tree.get_children())
        rows = [ap for ap in self.aps.values() if self._matches_security_filter(ap)]

        if self._sort_col is None:
            rows.sort(key=lambda ap: ap.bssid)
        else:
            key_fn = {
                "bssid": lambda ap: ap.bssid,
                "ssid": lambda ap: (ap.ssid or "").lower(),
                "channel": lambda ap: ap.channel if ap.channel is not None else -1,
                "security": lambda ap: ap.security or "",
                "pmf": lambda ap: ap.pmf or "",
                "wps": lambda ap: ap.wps or "",
                "signal": lambda ap: ap.signal if ap.signal is not None else -999,
            }[self._sort_col]
            rows.sort(key=key_fn, reverse=self._sort_reverse)

        wps_display = {"enabled": "yes", "locked": "locked"}
        for i, ap in enumerate(rows):
            band_tag = "row_even" if i % 2 == 0 else "row_odd"
            self.tree.insert("", tk.END, iid=ap.bssid, values=(
                ap.bssid, self._display_ssid(ap.ssid) if ap.ssid else "<hidden>", ap.channel or "-", ap.security or "-",
                ap.pmf or "-", wps_display.get(ap.wps, "-"), ap.signal if ap.signal is not None else "-",
            ), tags=((ap.security or "unknown").lower(), band_tag))
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)

    def _on_target_heading_click(self, col: str):
        """Click a column heading to sort by it; click again to reverse."""
        numeric_cols = {"channel", "signal"}
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = col in numeric_cols
        for key, heading, _width in TARGET_COLUMNS:
            if self._sort_col == key:
                arrow = "▼" if self._sort_reverse else "▲"
                self.tree.heading(key, text=f"{heading} {arrow}")
            else:
                self.tree.heading(key, text=heading)
        self._render_targets()

    def _on_target_right_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == "heading":
            self._show_column_menu(event)
            return
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.root.clipboard_clear()
        self.root.clipboard_append(row)
        self.status_var.set(f"Copied BSSID {row} to clipboard")

    def _on_client_right_click(self, event):
        row = self.client_tree.identify_row(event.y)
        if not row:
            return
        self.client_tree.selection_set(row)
        menu = tk.Menu(self.root, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        menu.add_command(label="Deauth This Client", command=self._attack_deauth_client)
        menu.add_command(label="Copy MAC", command=lambda: self._copy_to_clipboard(row))
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"Copied {text} to clipboard")

    def _apply_column_visibility(self):
        """displaycolumns, not width=0 — a zero-width column is still a
        clickable sliver in ttk.Treeview, this actually removes it."""
        visible = [key for key, _, _ in TARGET_COLUMNS if key not in self.hidden_columns]
        self.tree["displaycolumns"] = visible

    def _show_column_menu(self, event):
        """Right-click a column header to show/hide it (deferred earlier
        since it wanted settings persistence first — now wired to it).
        BSSID stays pinned, it's the row identity, same as it's excluded
        from sorting."""
        menu = tk.Menu(self.root, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        for key, heading, _width in TARGET_COLUMNS:
            if key == "bssid":
                continue
            var = tk.BooleanVar(value=key not in self.hidden_columns)

            def toggle(key=key, var=var):
                if var.get():
                    self.hidden_columns.discard(key)
                else:
                    self.hidden_columns.add(key)
                self._apply_column_visibility()

            menu.add_checkbutton(label=heading, variable=var, command=toggle)
        menu.tk_popup(event.x_root, event.y_root)

    def _on_target_select(self, _event=None):
        """Fires on both a real user click AND _render_targets()'s own
        tree.selection_set(selected) call that restores the selection
        after every scan-update redraw -- ttk.Treeview refires
        <<TreeviewSelect>> on selection_set() even when the selection
        didn't change. Without the is_new_bssid guard below, that meant
        signal_graph.reset() ran on every single scan tick, wiping the
        history back down to one seeded sample every time -- the graph
        could never show more than a single (moving) dot (2026-08-27 user
        report)."""
        sel = self.tree.selection()
        if not sel:
            return
        bssid = sel[0]
        self.selected_bssid = bssid
        ap = self.aps.get(bssid)
        if not ap:
            return
        is_new_bssid = bssid != self._last_graphed_bssid
        self._last_graphed_bssid = bssid
        self.target_title_var.set(f"{ap.ssid or '<hidden>'}  ({bssid})")
        self.target_detail_var.set(
            f"BSSID: {bssid}\n"
            f"Channel: {ap.channel or '-'}\n"
            f"Security: {ap.security or '-'}\n"
            f"PMF: {ap.pmf or '-'}\n"
            f"Signal: {ap.signal if ap.signal is not None else '-'} dBm\n"
            f"Clients seen: {len(ap.clients)}"
        )
        # _on_target_select refires on every scan-tick redraw (see docstring
        # above), not just on a real click. Blindly delete()+insert()ing the
        # client_tree every time wiped the user's row selection out from
        # under them on the very next scan hop -- clicking a client above/
        # below the currently-selected one looked "stuck" because any
        # selection made between two ticks got destroyed before it could be
        # acted on. Only touch the tree structure when the client set
        # actually changed; otherwise just refresh signal values in place
        # and leave the existing selection alone. When it does change,
        # carry the previous selection forward if that client is still present.
        current_ids = self.client_tree.get_children()
        new_ids = tuple(sorted(ap.clients))
        if current_ids == new_ids:
            for mac in new_ids:
                signal = ap.client_signal.get(mac)
                self.client_tree.item(mac, values=(mac, signal if signal is not None else "-"))
        else:
            prev_selection = self.client_tree.selection()
            self.client_tree.delete(*current_ids)
            for i, mac in enumerate(new_ids):
                signal = ap.client_signal.get(mac)
                band_tag = "row_even" if i % 2 == 0 else "row_odd"
                self.client_tree.insert(
                    "", tk.END, iid=mac, values=(mac, signal if signal is not None else "-"), tags=(band_tag,),
                )
            still_present = [mac for mac in prev_selection if mac in new_ids]
            if still_present:
                self.client_tree.selection_set(still_present)

        if not is_new_bssid:
            return
        # Seed with the last-known signal so the graph isn't empty while
        # waiting for the next scan hop to land on this AP's channel.
        self.signal_graph.reset()
        if ap.last_signal is not None:
            self.signal_graph.add_sample(ap.last_signal)
        self._start_selected_capture_watch(ap)
        if ap.channel:
            self._lock_channel(ap)

    def _start_selected_capture_watch(self, ap: AccessPoint):
        """Live KB readout of any existing capture data for the selected
        target. Reads whatever's already on disk; a running attack's own
        _watch_capture_size call takes priority and this backs
        off (checked via self._busy) so the two don't fight over the same
        capture_size_var."""
        if self._select_capture_watch_stop is not None:
            self._select_capture_watch_stop.set()
        stop_event = threading.Event()
        self._select_capture_watch_stop = stop_event

        from ..storage import target_capture_dir

        capture_dir = target_capture_dir(ap.ssid, ap.bssid, create=False)

        def watch():
            while not stop_event.is_set():
                if not self._busy:
                    try:
                        size = sum(f.stat().st_size for f in capture_dir.glob("**/*") if f.is_file()) \
                            if capture_dir.exists() else 0
                    except OSError:
                        size = 0
                    self._queue.put(("capture_size", size))
                stop_event.wait(1)

        threading.Thread(target=watch, daemon=True).start()

    def _on_target_double_click(self, _event=None):
        """Redundant with single-click since 2026-08-26 (select now locks
        too, see _on_target_select) — harmless no-op re-lock, kept so
        double-click still does something sensible rather than nothing."""
        bssid = self.selected_bssid
        if not bssid:
            return
        ap = self.aps.get(bssid)
        if ap and ap.channel:
            self._lock_channel(ap)

    def _selected_client(self) -> str | None:
        sel = self.client_tree.selection()
        return sel[0] if sel else None

    def _lock_channel(self, ap: AccessPoint):
        """Stop hopping and park the adapter on ap's channel. Also
        starts a native packet capture restricted to this bssid so the
        capture-size KB readout actually grows from real on-disk data,
        not just a static existing-file check."""
        if self.channel_locked and self.locked_bssid == ap.bssid and self._lock_capture_proc is not None:
            return  # already locked to this exact target with a live capture running
        if ap.channel is None:
            self._log(f"No channel known for {ap.bssid}; cannot lock")
            return
        self.channel_locked = True
        self.locked_bssid = ap.bssid
        self.locked_channel = ap.channel
        self._lock_lost_since = None
        self._scan_channels = [ap.channel]
        # No reset here: _on_target_select already reset+seeded the graph
        # for this same bssid (selection always fires before/with the
        # double-click that reaches this method) — resetting again would
        # just throw away that seed point for no reason.
        self.channel_lock_var.set(f"🔒 Locked to CH {ap.channel}")
        self.lock_status_label.configure(fg=self.THEME["accent"])
        self._log(f"Locked to channel {ap.channel} for {ap.ssid or '<hidden>'} ({ap.bssid})")
        if self.mon_iface and "demo" not in self.mon_iface:
            def work():
                from ..radio import ensure_channel

                ensure_channel(self.mon_iface, ap.channel)
                return f"channel {ap.channel}"

            self._run_bg(f"Set channel {ap.channel}", work)
            self._start_lock_capture(ap)

    def _start_lock_capture(self, ap: AccessPoint):
        """Native AsyncSniffer-backed capture (lock_capture.LockCapture),
        restricted to ap's bssid on the already-locked channel, writing
        continuously to disk. Stopped by _unlock_channel/_stop_lock_capture."""
        assert self.mon_iface is not None
        self._stop_lock_capture()
        import time as _time

        from ..lock_capture import LockCapture
        from ..storage import target_capture_dir

        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"lock_{int(_time.time())}.pcap"
        try:
            capture = LockCapture(self.mon_iface, ap.bssid, str(out_file))
            capture.start()
            self._lock_capture_proc = capture
        except OSError as exc:
            self._log(f"lock capture failed to start: {exc}")
            self._lock_capture_proc = None

    def _stop_lock_capture(self):
        capture = self._lock_capture_proc
        self._lock_capture_proc = None
        if capture is None:
            return
        capture.stop()

    def _unlock_channel(self):
        """Resume hopping the full channel range."""
        if not self.channel_locked:
            return
        self.channel_locked = False
        self.locked_bssid = None
        self.locked_channel = None
        self._lock_lost_since = None
        self._scan_channels = None
        self._stop_lock_capture()
        self.channel_lock_var.set("Scanning all channels")
        self.lock_status_label.configure(fg=self.THEME["error"])
        self._log("Channel lock released; scanning all channels")

    def _check_channel_lock(self):
        """Auto-unlock if the locked target hasn't been seen for CHANNEL_LOCK_TIMEOUT."""
        if self.channel_locked and self.locked_bssid and self.locked_bssid not in self.aps:
            import time

            if self._lock_lost_since is None:
                self._lock_lost_since = time.monotonic()
            elif time.monotonic() - self._lock_lost_since > CHANNEL_LOCK_TIMEOUT:
                self._log("Locked target hasn't been seen in 30s; channel lock auto-released")
                self._unlock_channel()
        self.root.after(5000, self._check_channel_lock)

    def _require_target(self) -> AccessPoint | None:
        if not self.selected_bssid or self.selected_bssid not in self.aps:
            messagebox.showwarning("ATWA-NG", "Select a target from the scan list first.")
            return None
        if not self.mon_iface:
            messagebox.showwarning("ATWA-NG", "Start monitor mode first.")
            return None
        return self.aps[self.selected_bssid]

    # ------------------------------------------------------------------
    # Attacks — every call below hits this project's own native implementation.
    # ------------------------------------------------------------------
    def _confirm_attack(self, title: str, detail: str) -> bool:
        """Modal countdown confirm before firing an attack. Attacks are
        native calls, not shell commands, so this shows a plain-English
        summary instead of a literal command line. Auto-confirms at 0
        unless Cancelled; Execute Now skips the wait. Blocks
        (wait_window) until a choice is made."""
        result = {"go": False}
        dlg = tk.Toplevel(self.root)
        dlg.title("Confirm Attack")
        dlg.configure(bg=self.THEME["bg"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        ttk.Label(dlg, text=title, style="Heading.TLabel").pack(padx=16, pady=(14, 4))
        ttk.Label(dlg, text=detail, style="Muted.TLabel", justify=tk.LEFT, wraplength=380).pack(padx=16, pady=(0, 10))
        count_var = tk.StringVar(value="Executing in 3...")
        ttk.Label(dlg, textvariable=count_var, font=self.fonts["ui_bold"]).pack(pady=(0, 10))

        remaining = [3]
        after_id: list[str | None] = [None]

        def go():
            if after_id[0]:
                dlg.after_cancel(after_id[0])
            result["go"] = True
            dlg.destroy()

        def cancel():
            if after_id[0]:
                dlg.after_cancel(after_id[0])
            result["go"] = False
            dlg.destroy()

        def tick():
            remaining[0] -= 1
            if remaining[0] <= 0:
                go()
                return
            count_var.set(f"Executing in {remaining[0]}...")
            after_id[0] = dlg.after(1000, tick)

        btns = ttk.Frame(dlg)
        btns.pack(pady=(0, 14))
        ttk.Button(btns, text="Cancel", command=cancel, style="Danger.TButton").pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Execute Now", command=go, style="Accent.TButton").pack(side=tk.LEFT, padx=6)

        dlg.protocol("WM_DELETE_WINDOW", cancel)
        after_id[0] = dlg.after(1000, tick)
        dlg.wait_window()
        return result["go"]

    def _attack_deauth_all(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack("Deauth All Clients", f"Send 64 deauth frames to ALL clients on {ap.bssid} ({ap.ssid or '<hidden>'})."):
            return
        self._run_bg(f"Deauth all clients on {ap.bssid}", self._runner().deauth_all, ap)

    def _attack_deauth_client(self):
        ap = self._require_target()
        if not ap:
            return
        client = self._selected_client()
        if not client:
            messagebox.showwarning("ATWA-NG", "No client selected — pick one from the Clients list.")
            return
        if not self._confirm_attack("Deauth Client", f"Send 64 deauth frames to {client} on {ap.bssid} ({ap.ssid or '<hidden>'})."):
            return
        self._run_bg(f"Deauth {client} on {ap.bssid}", self._runner().deauth_client, ap, client)

    def _attack_pmkid(self):
        ap = self._require_target()
        if not ap:
            return
        if not self.own_mac:
            messagebox.showwarning("ATWA-NG", "Own MAC not known yet — restart monitor mode.")
            return
        if not self._confirm_attack("PMKID Attack", f"Clientless PMKID capture against {ap.bssid} ({ap.ssid or '<hidden>'})."):
            return
        self._run_bg(f"PMKID attack on {ap.bssid}", self._runner().pmkid, ap)

    def _attack_handshake(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack("Handshake Capture", f"Sniff EAPOL on {ap.bssid} ({ap.ssid or '<hidden>'}) for up to 60s."):
            return

        def work():
            return self._runner().handshake(ap)

        self._run_bg(f"Handshake capture on {ap.bssid}", work)

    def _attack_smart(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack("Smart Attack", f"Run full Smart Attack chain against {ap.bssid} ({ap.ssid or '<hidden>'}) — includes deauth rounds."):
            return
        self._run_bg(f"Smart Attack on {ap.bssid}", self._runner().smart, ap)

    def _attack_omni(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack("OMNI Attack", f"Run full OMNI Attack chain against {ap.bssid} ({ap.ssid or '<hidden>'}) — includes deauth rounds."):
            return
        self._run_bg(f"OMNI Attack on {ap.bssid}", self._runner().omni, ap)

    def _attack_wep(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "WEP attack needs a known SSID (this AP's SSID hasn't been seen yet).")
            return
        if not self.own_mac:
            messagebox.showwarning("ATWA-NG", "Own MAC not known yet — restart monitor mode.")
            return
        key_len = 13
        if not messagebox.askyesno("ATWA-NG", "WEP attack: use WEP-104 (13-byte key)? Choose No for WEP-40 (5-byte)."):
            key_len = 5
        if not self._confirm_attack("WEP Attack", f"Fake-auth + ARP replay + PTW key recovery against {ap.bssid} ({ap.ssid})."):
            return
        self._run_bg(f"WEP attack on {ap.bssid}", self._runner().wep, ap, key_len)

    def _attack_caffe_latte(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.clients:
            messagebox.showwarning("ATWA-NG", "Caffe Latte needs a visible client — lock a WEP AP with at least one client listed.")
            return
        client_mac = next(iter(ap.clients))
        key_len = 13 if messagebox.askyesno("ATWA-NG", "WEP Caffe Latte: use WEP-104 (13-byte)? No = WEP-40 (5-byte).") else 5
        if not self._confirm_attack(
            "WEP Caffe Latte",
            f"Client-only WEP attack against {client_mac} (client of {ap.bssid}).\n"
            "No AP association needed — replays client ARPs to collect IVs.",
        ):
            return
        self._run_bg(f"Caffe Latte on {client_mac}", self._runner().caffe_latte, client_mac, ap, key_len)

    def _attack_chopchop(self):
        """DISABLED (2026-08-25): the native ICV-correction math doesn't
        work through WEP's RC4 encryption — confirmed by two independent
        offline verification tests, not just a live failure. See the
        comment above attacks/wep_client.py's chopchop(). The project's
        own compiled injection engine (vendor/aircrack-ng) already has a
        real, working chopchop attack; driving it from here is future
        work."""
        messagebox.showwarning(
            "ATWA-NG",
            "WEP Chopchop is disabled — its decryption math doesn't work "
            "against real WEP encryption (verified offline, not just "
            "untested).\n\nThe project's own compiled injection engine "
            "already has a working chopchop attack — use that for now.",
        )

    def _attack_wps_null_pin(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "WPS attack needs a known SSID.")
            return
        if not self._confirm_attack("WPS Null-PIN", f"One-shot null-PIN attempt against {ap.bssid} ({ap.ssid})."):
            return
        self._run_bg(f"WPS null-PIN on {ap.bssid}", self._runner().wps_null_pin, ap)

    def _attack_wps_pixie(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "WPS attack needs a known SSID.")
            return
        if not self._confirm_attack(
            "WPS Pixie-Dust",
            f"Offline pixie-dust against {ap.bssid} ({ap.ssid}).\n"
            "Requires one M1→M3 exchange to capture crypto material.",
        ):
            return
        self._run_bg(f"WPS pixie-dust on {ap.bssid}", self._runner().wps_pixie, ap)

    def _attack_wps_bruteforce(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "WPS attack needs a known SSID.")
            return
        warned = messagebox.askokcancel(
            "ATWA-NG",
            "WPS bruteforce is currently EXPERIMENTAL — across multiple live sessions "
            "it has never completed a real M2→M3 exchange against a test AP (see "
            "STATUS.md). It may just time out repeatedly. Continue anyway?",
        )
        if not warned:
            return
        self._run_bg(f"WPS bruteforce on {ap.bssid}", self._runner().wps_bruteforce, ap)

    def _stop_attack(self):
        self._stop_event.set()
        self.auto_deauth_var.set(False)
        if hasattr(self, "_auto_deauth_stop"):
            self._auto_deauth_stop.set()
        crack_proc = self._crack_proc_holder.get("proc")
        if crack_proc is not None and crack_proc.poll() is None:
            crack_proc.terminate()
            self._log("stop requested: terminated the running crack process (John/aircrack-ng)")
        self._log("stop requested (OMNI/Smart/WPS-bruteforce/auto-deauth loops will exit at their "
                   "next check; a single blocking call in progress will still finish on its own timeout)")

    def _toggle_auto_deauth(self):
        """'Auto-deauth until handshake': deauth the locked target on a
        timer, independent of OMNI/Smart, stopping itself once an
        AUTHORIZED handshake is actually captured — not just after N
        rounds. There's no continuous background EAPOL listener, so this
        starts its own: one thread blocks in capture_handshake() with a
        timeout sized to the round budget, a second thread sends the
        periodic deauth bursts; whichever condition hits first
        (AUTHORIZED capture, toggle turned off, or the round budget
        exhausted) ends the loop."""
        if not self.auto_deauth_var.get():
            if hasattr(self, "_auto_deauth_stop"):
                self._auto_deauth_stop.set()
            self._log("auto-deauth stopped")
            return
        ap = self._require_target()
        if not ap:
            self.auto_deauth_var.set(False)
            return
        if self._busy:
            messagebox.showwarning("ATWA-NG", "Another attack is already running. Use Stop Attack first.")
            self.auto_deauth_var.set(False)
            return
        self._auto_deauth_stop = threading.Event()
        interval = int(self.deauth_interval_var.get())
        self._log(f"auto-deauth started against {ap.bssid} (every {interval}s, stops itself on AUTHORIZED capture)")
        threading.Thread(target=self._auto_deauth_run, args=(ap, interval, self._auto_deauth_stop), daemon=True).start()

    def _format_capture_size(self, size: int | None) -> str:
        if size is None:
            return ""
        if size < 1024:
            return f"Capture: {size} B"
        if size < 1024 ** 2:
            return f"Capture: {size / 1024:.1f} KB"
        return f"Capture: {size / 1024 ** 2:.1f} MB"

    def _watch_capture_size(self, path, stop_event: threading.Event):
        """A live-growing capture-size readout (0 B -> ... KB) next to
        the signal graph, confirming data is actually landing on disk
        during a capture — not just that an attack is 'running'."""
        import time as _time
        from pathlib import Path

        p = Path(path)
        while not stop_event.is_set():
            try:
                size = p.stat().st_size if p.exists() else 0
            except OSError:
                size = 0
            self._queue.put(("capture_size", size))
            _time.sleep(1)
        self._queue.put(("capture_size", None))

    def _auto_deauth_run(self, ap: AccessPoint, interval: int, stop_event: threading.Event):
        assert self.mon_iface is not None
        assert ap.channel is not None
        import time as _time

        from ..attacks.deauth import deauth
        from ..attacks.handshake import HandshakeStatus, capture_handshake
        from ..storage import target_capture_dir

        max_rounds = 6
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"autodeauth_{int(_time.time())}.pcap"
        result: dict = {}

        def listen():
            result["cap"] = capture_handshake(
                self.mon_iface, ap.bssid, channel=ap.channel,
                timeout=interval * max_rounds + 10, outfile=str(out_file),
                stop_event=stop_event, progress_fn=self._log,
            )

        # Marks mon_iface busy so the background scan loop (_start_scan)
        # stops opening its own competing sniff() socket on the same
        # interface for the duration of this run — this bypasses _run_bg
        # (toggle checkbox, not a one-shot attack), so it never set
        # self._busy before, letting the scan loop's per-hop socket churn
        # starve both the deauth TX and the handshake-capture RX.
        self._queue.put(("busy", True))
        try:
            listener = threading.Thread(target=listen, daemon=True)
            listener.start()
            watch_stop = threading.Event()
            threading.Thread(target=self._watch_capture_size, args=(out_file, watch_stop), daemon=True).start()

            def authorized() -> bool:
                cap = result.get("cap")
                return bool(cap and any(cap.status(a, c) is HandshakeStatus.AUTHORIZED for a, c in cap.messages))

            for round_n in range(max_rounds):
                if stop_event.is_set():
                    break
                try:
                    sent = deauth(self.mon_iface, ap.bssid, channel=ap.channel, progress_fn=self._log)
                    if sent == 0:
                        self._log(f"auto-deauth round {round_n + 1}/{max_rounds}: did NOT go out to {ap.bssid} — see the warning above")
                    else:
                        self._log(f"auto-deauth round {round_n + 1}/{max_rounds}: sent {sent} deauth frame(s) to {ap.bssid}")
                except Exception as exc:  # noqa: BLE001 - auto-deauth loop must survive per-round errors
                    self._log(f"auto-deauth round {round_n + 1} failed: {exc}")
                for _ in range(interval):
                    if stop_event.is_set() or authorized():
                        break
                    _time.sleep(1)
                if authorized():
                    break

            listener.join(timeout=5)
            watch_stop.set()
            if authorized():
                self._log(f"auto-deauth: AUTHORIZED handshake captured -> {out_file}")
            else:
                self._log("auto-deauth: stopped or exhausted rounds, no AUTHORIZED handshake")
        finally:
            self._queue.put(("busy", False))
            self._queue.put(("auto_deauth_done", None))

    def _attack_eviltwin(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "Evil Twin needs a known SSID.")
            return
        iface_ap = self.iface_ap_var.get().strip()
        if not iface_ap:
            messagebox.showerror(
                "ATWA-NG",
                "No AP interface configured.\n\n"
                "Pick one in the toolbar's 'AP iface' dropdown (the ACHM "
                "adapter, in managed mode, distinct from the scan/monitor "
                "adapter).",
            )
            return
        if iface_ap == self.mon_iface:
            messagebox.showerror(
                "ATWA-NG",
                f"AP interface ({iface_ap}) is the same as the monitor "
                f"interface ({self.mon_iface}).\n\n"
                "Evil Twin needs two separate adapters: one to host the "
                "rogue AP, one to stay in monitor mode for deauth.",
            )
            return
        if not self._confirm_attack(
            "Evil Twin",
            f"Rogue AP + captive portal against {ap.bssid} ({ap.ssid}).\n\n"
            f"AP interface: {iface_ap}  |  Monitor: {self.mon_iface}\n"
            "Will deauth real clients and serve a password-harvest portal.",
        ):
            return
        self._run_bg(f"Evil Twin on {ap.bssid}", self._runner().eviltwin, ap, iface_ap)

    def _attack_online_guess(self):
        """Live per-password 4-way handshake attempt against the AP itself
        (attacks/online.py) -- the standalone version of OMNI's ONLINE
        stage, for running it on its own instead of the full chain (e.g.
        PMF blocks the HANDSHAKE stage's deauth, so this is a way to still
        try a wordlist against the target)."""
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "Online guessing needs a known SSID.")
            return
        if ap.security not in ("WPA", "WPA2", "transition"):
            messagebox.showwarning(
                "ATWA-NG",
                f"Online guessing needs a PSK-based network (WPA/WPA2/transition) — "
                f"this target is {ap.security}. WPA3/SAE-only and WEP aren't supported "
                "(see attacks/online.py).",
            )
            return
        if not self.own_mac:
            messagebox.showwarning("ATWA-NG", "Own MAC not known yet — restart monitor mode.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return
        if not self._confirm_attack(
            "Online Password Guess",
            f"Live password guessing against {ap.bssid} ({ap.ssid}) using {wordlist}.\n\n"
            "Slow by design (one real association + 4-way handshake per candidate, "
            "~1-3s each) and noisy — every attempt is visible to the AP.",
        ):
            return
        self._run_bg(f"Online guess on {ap.bssid}", self._runner().online_guess, ap)

    def _attack_pincer(self):
        """Flagship dual-Alfa mode (STATUS.md 'Ideas/undecided', 2026-08-14
        — one special locked/hidden attack, not folded into the default
        single-adapter path). Split-role, proven live that session: the
        AWUS036ACHM (mt76x0u, wider scan range) stays parked on the
        target's channel doing nothing but listen for the handshake, while
        the AWUS1900 (rtw88_8814au, 4 antennas) does nothing but hammer
        deauth — neither radio ever time-shares between scanning and
        attacking, unlike single-adapter mode. Gated entirely on
        radio.detect_alfa_pair(); the menu entry is disabled without both
        specific adapters present."""
        ap = self._require_target()
        if not ap:
            return
        if not self.alfa_pair:
            messagebox.showwarning("ATWA-NG", "PINCER needs both Alfa adapters connected (AWUS036ACHM + AWUS1900).")
            return
        scan_iface, attack_iface = self.alfa_pair
        if not self._confirm_attack(
            "PINCER (Dual-Alfa)",
            f"{scan_iface} listens on {ap.bssid} ({ap.ssid or '<hidden>'}) while {attack_iface} "
            f"deauths continuously. Both radios go to monitor mode and back when done.",
        ):
            return
        self._run_bg(
            f"PINCER on {ap.bssid}",
            self._runner().pincer,
            ap, scan_iface, attack_iface, self.randomize_mac_var.get(),
            self._watch_capture_size,
        )

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Captures tab
    # ------------------------------------------------------------------
    def _capture_files(self):
        from pathlib import Path

        root = Path(self.capture_dir_var.get())
        if not root.exists():
            return []
        suffixes = {".cap", ".pcap", ".pcapng", ".22000"}
        return sorted((p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in suffixes),
                      key=lambda p: p.stat().st_mtime, reverse=True)

    def _refresh_captures(self):
        self.capture_tree.delete(*self.capture_tree.get_children())
        for i, path in enumerate(self._capture_files()):
            size = path.stat().st_size
            size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB" if size < 1024 ** 2 else f"{size / 1024 ** 2:.1f} MB"
            kind = "hash" if path.suffix.lower() == ".22000" else "capture"
            band_tag = "row_even" if i % 2 == 0 else "row_odd"
            self.capture_tree.insert(
                "", tk.END, iid=str(path), values=(path.name, kind, size_str, str(path)), tags=(band_tag,),
            )

    def _selected_capture_paths(self) -> list[str]:
        return list(self.capture_tree.selection())

    def _on_capture_right_click(self, event):
        row = self.capture_tree.identify_row(event.y)
        if not row:
            return
        if row not in self.capture_tree.selection():
            self.capture_tree.selection_set(row)
        self._capture_copy_path()

    def _capture_copy_path(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("ATWA-NG", "Select a capture first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(paths))
        self.status_var.set(f"Copied {len(paths)} path(s) to clipboard")

    def _capture_inspect(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("ATWA-NG", "Select a capture first.")
            return

        def work():
            from pathlib import Path

            lines = []
            for p in paths:
                path = Path(p)
                if path.suffix.lower() == ".22000":
                    text = path.read_text()
                    pmkid = sum(1 for line in text.splitlines() if line.startswith("WPA*01*"))
                    hs = sum(1 for line in text.splitlines() if line.startswith("WPA*02*"))
                    lines.append(f"{path.name}: {pmkid} PMKID line(s), {hs} handshake line(s)")
                else:
                    lines.append(f"{path.name}: {self._inspect_capture(path)}")
            self._queue.put(("info", "\n".join(lines)))
            return "inspected"

        self._run_bg("Inspect capture(s)", work)

    def _inspect_capture(self, path) -> str:
        from scapy.utils import rdpcap

        from ..attacks.handshake import HandshakeCapture, _classify
        from ..attacks.pmkid import extract_pmkid
        from ..frames import is_eapol

        try:
            packets = rdpcap(str(path))
        except Exception as exc:  # noqa: BLE001 - capture parse failures are reported, not fatal
            return f"could not parse ({exc})"
        cap = HandshakeCapture()
        pmkid_found = False
        for pkt in packets:
            if is_eapol(pkt) and extract_pmkid(bytes(pkt)):
                pmkid_found = True
            msg_no = _classify(pkt)
            if msg_no is not None and getattr(pkt, "addr3", None) and getattr(pkt, "addr1", None):
                ap, client = pkt.addr3, pkt.addr1 if msg_no % 2 == 1 else pkt.addr2
                cap.add(ap, client, msg_no)
        statuses = [cap.status(a, c).value for a, c in cap.messages]
        parts = [f"{len(packets)} packets"]
        if pmkid_found:
            parts.append("PMKID present")
        if statuses:
            parts.append(f"handshake pairs={statuses}")
        if not pmkid_found and not statuses:
            parts.append("no PMKID/handshake material found")
        return ", ".join(parts)

    def _capture_convert(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("ATWA-NG", "Select a .cap/.pcap/.pcapng file first.")
            return
        from ..crack.convert import cap_to_22000

        def work():
            results = []
            for p in paths:
                out = p + ".22000"
                cap_to_22000(p, out)
                results.append(out)
            self._queue.put(("info", "Converted:\n" + "\n".join(results)))
            self._queue.put(("status", "Ready."))
            self.root.after(0, self._refresh_captures)
            return "converted"

        self._run_bg("Convert to 22000", work)

    def _capture_fix(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("ATWA-NG", "Select a capture to fix first.")
            return
        from ..crack.convert import fix_capture

        def work():
            outputs = [fix_capture(p) for p in paths]
            self._queue.put(("info", "Fixed:\n" + "\n".join(outputs)))
            self.root.after(0, self._refresh_captures)
            return "fixed"

        self._run_bg("Fix capture(s)", work)

    def _capture_merge(self):
        paths = self._selected_capture_paths()
        if len(paths) < 2:
            messagebox.showwarning("ATWA-NG", "Select at least two captures to merge.")
            return
        from ..crack.convert import merge_captures

        def work():
            out = merge_captures(paths)
            self._queue.put(("info", f"Merged into:\n{out}"))
            self.root.after(0, self._refresh_captures)
            return out

        self._run_bg("Merge captures", work)

    def _open_crack_dialog(self):
        CrackDialog(self.root, self.fonts, self.capture_dir_var.get(), self.wordlist_var.get())

    def _open_wps_scan(self):
        """Live table of currently-known WPS-capable APs (manufacturer/model/
        device name -- already collected passively by every normal scan pass
        via secure.py's wps_profile(), just never surfaced anywhere in the
        GUI before). Unlike v1's WPS Scan popup (read-only, nothing in it is
        clickable -- 2026-08-27 user report), double-click a row to lock that
        target in the main window, matching what you'd actually want to do
        with a WPS recon result."""
        win = tk.Toplevel(self.root)
        win.title("WPS Scan")
        win.configure(bg=self.THEME["bg"])
        win.geometry("840x420")
        win.transient(self.root)

        ttk.Button(win, text="Refresh", command=lambda: self._refresh_wps_scan(tree)).pack(
            anchor=tk.NE, padx=6, pady=(6, 0))

        cols = ("bssid", "channel", "signal", "wps", "manufacturer", "model", "ssid")
        tree = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        headings = {
            "bssid": "BSSID", "channel": "CH", "signal": "Signal", "wps": "WPS",
            "manufacturer": "Manufacturer", "model": "Model", "ssid": "ESSID",
        }
        widths = {"bssid": 150, "channel": 45, "signal": 75, "wps": 75, "manufacturer": 140, "model": 150, "ssid": 170}
        for key in cols:
            tree.heading(key, text=headings[key])
            tree.column(key, width=widths[key], minwidth=40)
        vsb = ttk.Scrollbar(win, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=6)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=6)

        def lock_selected(_event=None):
            sel = tree.selection()
            if not sel:
                return
            bssid = sel[0]
            if bssid not in self.aps:
                return
            win.destroy()
            self.tree.selection_set(bssid)
            self._on_target_select()

        tree.bind("<Double-1>", lock_selected)

        menu = tk.Menu(win, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        menu.add_command(label="Lock This Target", command=lock_selected)
        menu.add_command(label="Copy BSSID", command=lambda: self._copy_to_clipboard(tree.selection()[0]) if tree.selection() else None)

        def on_right_click(event):
            row = tree.identify_row(event.y)
            if not row:
                return
            tree.selection_set(row)
            menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", on_right_click)

        self._refresh_wps_scan(tree)

    def _refresh_wps_scan(self, tree: ttk.Treeview):
        tree.delete(*tree.get_children())
        rows = [ap for ap in self.aps.values() if ap.wps]
        rows.sort(key=lambda ap: ap.signal if ap.signal is not None else -999, reverse=True)
        for ap in rows:
            tree.insert("", tk.END, iid=ap.bssid, values=(
                ap.bssid, ap.channel or "-", ap.signal if ap.signal is not None else "-", ap.wps,
                ap.wps_manufacturer or "-", ap.wps_model_name or "-", ap.ssid or "<hidden>",
            ))

    def _capture_crack(self):
        """Crack the selected file(s): .22000 -> John, .cap/.pcap/.pcapng ->
        aircrack-ng (simpler for a single known target, per user request —
        needs a BSSID, derived from the target folder name)."""
        selected = self._selected_capture_paths()
        hash_paths = [p for p in selected if p.endswith(".22000")]
        cap_paths = [p for p in selected if p.lower().endswith((".cap", ".pcap", ".pcapng"))]
        if not hash_paths and not cap_paths:
            messagebox.showwarning("ATWA-NG", "Select one or more .22000 hash files or capture files first.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return

        if hash_paths:
            self._crack_with_john(hash_paths, wordlist)
        else:
            self._crack_with_aircrack(cap_paths, wordlist)

    def _crack_with_john(self, paths: list[str], wordlist: str):
        from ..crack.convert import merge_22000_files
        from ..crack.john import JohnCracker, JohnUnavailableError

        def work():
            from pathlib import Path

            hashfile = paths[0]
            if len(paths) > 1:
                merged_lines = merge_22000_files(paths)
                hashfile = str(Path(self.capture_dir_var.get()) / "merged_batch.22000")
                Path(hashfile).write_text("\n".join(merged_lines) + "\n")
            try:
                cracker = JohnCracker()
            except JohnUnavailableError as exc:
                return str(exc)
            self._crack_proc_holder.clear()
            results = cracker.run_streaming(hashfile, wordlist, self._progress_fn, self._crack_proc_holder)
            if not results:
                return "no passwords recovered"
            self._queue.put(("info", "\n".join(f"{k}: {v}" for k, v in results.items())))
            return f"{len(results)} recovered"

        self._run_bg("Crack with John", work)

    def _crack_with_aircrack(self, paths: list[str], wordlist: str):
        import re
        from pathlib import Path

        from ..crack.aircrack import AirCracker, AircrackUnavailableError
        from ..crack.convert import merge_captures

        bssid_match = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})$", Path(paths[0]).parent.name)
        if not bssid_match:
            messagebox.showwarning(
                "ATWA-NG",
                "Couldn't determine the BSSID from this file's folder name — aircrack-ng needs one "
                "to avoid its interactive network picker. Use 'Crack Handshakes (folder)...' instead, "
                "which lets you type a BSSID directly.",
            )
            return
        bssid = bssid_match.group(1).replace("-", ":").lower()

        def work():
            capfile = paths[0] if len(paths) == 1 else merge_captures(paths)
            try:
                cracker = AirCracker(bssid)
            except AircrackUnavailableError as exc:
                return str(exc)
            self._crack_proc_holder.clear()
            results = cracker.run_streaming(capfile, wordlist, self._progress_fn, self._crack_proc_holder)
            if not results:
                return "no password recovered"
            self._queue.put(("info", "\n".join(f"{k}: {v}" for k, v in results.items())))
            return f"cracked: {results.get(bssid)}"

        self._run_bg(f"Crack with aircrack-ng ({bssid})", work)

    def _capture_cleanup(self):
        """Preview then run housekeeping.cleanup_handshakes — merges each
        target's captures/hashes down to one file, then all targets into
        one master, deleting originals only after each merge is written.
        Destructive, so this always previews (dry_run) before asking."""
        from ..housekeeping import cleanup_handshakes

        plan = cleanup_handshakes(dry_run=True)
        if not plan.targets:
            messagebox.showinfo("ATWA-NG", "No target folders with captures to clean up.")
            return
        total_caps = sum(len(t.cap_files) for t in plan.targets)
        total_hashes = sum(len(t.hash_files) for t in plan.targets)
        preview = (
            f"{len(plan.targets)} target folder(s), {total_caps} capture file(s) + "
            f"{total_hashes} hash file(s) total.\n\n"
            "This will:\n"
            "  1. Merge each target's own captures/hashes into one file\n"
            "  2. Merge all targets together into one master capture + one master hash file\n"
            "  3. DELETE every original file once it's safely folded into the merged output\n"
            "  4. Remove any target folder left empty afterward\n\n"
            "This cannot be undone. Continue?"
        )
        if not messagebox.askokcancel("Cleanup Handshakes", preview):
            return

        def work():
            report = cleanup_handshakes(dry_run=False)
            self._queue.put(("info", report.summary()))
            self.root.after(0, self._refresh_captures)
            return f"{len(report.deleted)} file(s) deleted, {len(report.removed_dirs)} folder(s) removed"

        self._run_bg("Cleanup handshakes", work)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    def _choose_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist")
        if path:
            self.wordlist_var.set(path)

    def _choose_capture_dir(self):
        path = filedialog.askdirectory(title="Select capture folder")
        if path:
            self.capture_dir_var.set(path)
            self._refresh_captures()

    def _check_dependencies(self, *, startup: bool = False):
        from ..deps import check_all, missing_required

        statuses = check_all()
        missing = missing_required(statuses)
        if startup:
            # Quiet by default — only interrupt if something REQUIRED is
            # missing (app is largely nonfunctional without it). Optional
            # tools just get a one-line log summary instead of a modal
            # on every single launch.
            opt_missing = [s.name for s in statuses if not s.required and not s.found]
            if opt_missing:
                self._log(f"optional tools not found (some Captures actions disabled): {', '.join(opt_missing)}")
            else:
                self._log("all optional tools found")
            if missing:
                names = ", ".join(s.name for s in missing)
                messagebox.showwarning(
                    "ATWA-NG",
                    f"Required tool(s) missing: {names}\n\nMonitor mode/scanning will fail until these are installed.",
                )
            return

        lines = ["Required:"]
        for s in statuses:
            if not s.required:
                continue
            mark = "✓" if s.found else "✗ MISSING"
            lines.append(f"  {mark}  {s.name} — {s.feature}" + ("" if s.found else f"  ({s.apt})"))
        lines.append("\nOptional (gates one Captures action each):")
        for s in statuses:
            if s.required:
                continue
            mark = "✓" if s.found else "✗ missing"
            lines.append(f"  {mark}  {s.name} — {s.feature}" + ("" if s.found else f"  ({s.apt})"))
        messagebox.showinfo("Dependencies", "\n".join(lines))

    def _show_about(self):
        # Custom dialog, not messagebox.showinfo -- the built-in one can't
        # center its text or match the app's theme (2026-08-27 user
        # request: centered, links restored, tagline/long description
        # still trimmed as "unnecessary").
        win = tk.Toplevel(self.root)
        win.title("About ATWA-NG")
        win.configure(bg=self.THEME["bg"])
        win.resizable(False, False)
        win.transient(self.root)
        text = (
            f"ATWA-NG\nVersion {__version__}\n\n"
            "by KiMiGuel — INDEPENTEST LLC\n"
            "github.com/KiMiGuel\n"
            "indepentest.pro"
        )
        ttk.Label(win, text=text, justify=tk.CENTER, anchor=tk.CENTER).pack(padx=32, pady=(24, 12))
        ttk.Button(win, text="OK", command=win.destroy).pack(pady=(0, 16))
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{x}+{y}")

    def _load_demo_data(self):
        self.aps = {
            "22:87:ec:67:42:b1": AccessPoint(
                bssid="22:87:ec:67:42:b1", ssid="Indepentester", channel=1,
                security="WPA2", pmf="none", signal=-42, clients={"aa:bb:cc:dd:ee:01"},
            ),
            "de:ad:be:ef:00:01": AccessPoint(
                bssid="de:ad:be:ef:00:01", ssid="ExampleNet-5G", channel=44,
                security="WPA3", pmf="required", signal=-61, clients=set(),
            ),
            "de:ad:be:ef:00:02": AccessPoint(
                bssid="de:ad:be:ef:00:02", ssid=None, channel=6,
                security="open", pmf="none", signal=-70, clients={"11:22:33:44:55:66", "11:22:33:44:55:67"},
            ),
        }
        self.mon_iface = "wlan0mon (demo)"
        self.own_mac = "de:ad:be:ef:ff:ff"
        self.mac_var.set(self.own_mac)
        self.monitor_status_var.set(f"MONITOR: {self.mon_iface}")
        self._render_targets()
        self.tree.selection_set("22:87:ec:67:42:b1")
        self._on_target_select()
        import random

        random.seed(42)
        val = -42
        for _ in range(30):
            val += random.randint(-6, 6)
            self.signal_graph.add_sample(val)
        self._log("demo data loaded — no hardware touched")

    def _save_settings(self):
        self.settings.set("wordlist", self.wordlist_var.get())
        self.settings.set("capture_dir", self.capture_dir_var.get())
        self.settings.set("adapter", self.adapter_var.get())
        self.settings.set("iface_ap", self.iface_ap_var.get())
        self.settings.set("security_filter", self.security_filter_var.get())
        self.settings.set("randomize_mac", self.randomize_mac_var.get())
        self.settings.set("sort_col", self._sort_col)
        self.settings.set("sort_reverse", self._sort_reverse)
        self.settings.set("hidden_columns", sorted(self.hidden_columns))
        try:
            self.settings.save()
        except OSError as exc:
            self._log(f"could not save settings: {exc}")

    def _on_close(self):
        self._scanning.clear()
        self._stop_event.set()
        self._stop_lock_capture()
        # The scan loop thread (_start_scan) may be mid-blocking-sniff() when
        # _scanning is cleared -- sniff()'s call is timed (up to one dwell
        # period) and doesn't notice the flag until it returns. Without
        # waiting here, set_managed_mode() below (which does `ip link set
        # <iface> down`) could run while that thread's raw socket is still
        # open, yanking the interface out from under a live read -- this is
        # exactly the "[Errno 100] Network is down" scapy warning users see
        # on close, reproduced live (2026-08-27): AsyncSniffer left running
        # + set_managed_mode() called concurrently = deterministic ENETDOWN.
        # No driver quirk involved -- any open raw socket on an interface
        # that goes admin-down behaves this way, on any adapter. The join
        # timeout only needs to cover one dwell period plus loop overhead
        # (dwell defaults to 0.3s); 2s leaves comfortable margin.
        if self._scan_thread is not None:
            self._scan_thread.join(timeout=2.0)
        self._save_settings()
        if self.mon_iface and "demo" not in self.mon_iface:
            try:
                from ..radio import set_managed_mode

                set_managed_mode(self.mon_iface, restore_mac=self._permanent_mac)
            except Exception:  # noqa: BLE001, S110 - shutdown cleanup must be best-effort
                pass
        self.root.destroy()


def main(demo: bool = False) -> int:
    root = tk.Tk()
    App(root, demo=demo)
    root.mainloop()
    return 0
