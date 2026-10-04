"""Window chrome: menubar, toolbar, adapter selection, and the
settings/dependency checks.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..scan import AccessPoint
from .state import GuiState


class ToolbarMixin(GuiState):

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

    # ------------------------------------------------------------------
    # Menu bar — the resize-clip fix. Native window chrome, always reachable.
    # ------------------------------------------------------------------
    def _build_menubar(self):
        menubar = tk.Menu(self.root, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])

        file_menu = tk.Menu(menubar, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
        file_menu.add_command(label="Set Capture Folder...", command=self._choose_capture_dir)
        file_menu.add_command(label="Set Wordlist...", command=self._choose_wordlist)
        file_menu.add_command(label="Set John Ruleset...", command=self._choose_john_rules)
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
        attack_menu.add_command(label="CSA Spoof (channel redirect)", command=self._attack_csa_spoof)
        attack_menu.add_command(label="EAPOL-Start Flood", command=self._attack_eapol_flood)
        attack_menu.add_command(label="Auth Flood", command=self._attack_auth_flood)
        attack_menu.add_command(label="Beacon Flood", command=self._attack_beacon_flood)
        attack_menu.add_command(label="TKIP MIC Flood", command=self._attack_tkip_mic_flood)
        attack_menu.add_separator()
        attack_menu.add_command(label="Smart Attack (Auto)", command=self._attack_smart)
        attack_menu.add_command(label="OMNI Attack (All Stages)", command=self._attack_omni)
        attack_menu.add_command(label="WEP Attack", command=self._attack_wep)
        attack_menu.add_command(label="WEP Caffe Latte (client)", command=self._attack_caffe_latte)
        attack_menu.add_command(label="WEP Hirte (IBSS client)", command=self._attack_hirte)
        attack_menu.add_command(label="WEP Chopchop (decrypt)", command=self._attack_chopchop)
        attack_menu.add_command(label="WPS Null-PIN", command=self._attack_wps_null_pin)
        attack_menu.add_command(label="WPS Pixie-Dust (offline)", command=self._attack_wps_pixie)
        attack_menu.add_command(label="WPS Bruteforce (experimental)", command=self._attack_wps_bruteforce)
        attack_menu.add_command(label="Downgrade Twin (WPA3-transition, portal-free)", command=self._attack_downgrade_twin)
        attack_menu.add_command(label="PMF Bypass Reconnect (portal-free)", command=self._attack_pmf_bypass)
        attack_menu.add_command(label="OWE Downgrade (open-transition, portal-free)", command=self._attack_owe_downgrade)
        attack_menu.add_command(label="Online Password Guess (live, budgeted)", command=self._attack_online_guess)
        attack_menu.add_command(label="🩸 Dragonblood (SAE timing side-channel, unverified)",
                                 command=self._attack_dragonblood, foreground=self.THEME["error"])
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
        cap_menu.add_command(label="Inspect All", command=self._capture_inspect_all)
        cap_menu.add_command(label="Convert to 22000", command=self._capture_convert)
        cap_menu.add_command(label="Fix Capture", command=self._capture_fix)
        cap_menu.add_command(label="Merge Selected", command=self._capture_merge)
        cap_menu.add_command(label="Crack Selected", command=self._capture_crack)
        cap_menu.add_command(label="Copy Path", command=self._capture_copy_path)
        cap_menu.add_separator()
        cap_menu.add_command(label="Benchmark John", command=self._capture_benchmark_john)
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

    # ------------------------------------------------------------------
    # Toolbar — deliberately minimal (few widgets => unlikely to overflow
    # even on its own), authoritative access stays in the menu bar above.
    # ------------------------------------------------------------------
    def _build_toolbar(self):
        # Toolbar items wrap onto as many rows as needed instead of
        # overflowing off the visible window (2026-08-28 user report: a
        # fixed single row clipped "Unlock" and pushed the logo button off
        # entirely on screens under ~1400px). _reflow_toolbar reparents
        # these widgets into fresh row frames on every resize based on
        # actual measured width, so nothing is ever hidden -- only the
        # toolbar's own height grows.
        container = ttk.Frame(self.root, style="Toolbar.TFrame", padding=4)
        container.pack(side=tk.TOP, fill=tk.X)

        # Adapter/AP iface stacked in their own column (AP iface directly
        # under Adapter, per user request) -- keeps the two interface
        # pickers grouped and visually paired instead of strung out along
        # one long row with the action buttons.
        iface_col = ttk.Frame(container, style="Toolbar.TFrame")
        ttk.Label(iface_col, text="Adapter:", style="Toolbar.TLabel").grid(row=0, column=0, sticky=tk.W)
        # Chipset/vendor shown inside the dropdown itself ("wlan1
        # (Mediatek)"), not as a separate always-on label (2026-08-27 user
        # report, v1 reference has no such label) -- adapter_var still holds
        # just the bare iface name for every downstream radio call.
        self.adapter_combo = ttk.Combobox(iface_col, textvariable=self.adapter_display_var, state="readonly", width=20)
        self.adapter_combo.grid(row=0, column=1, padx=(4, 0))
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_adapter_selected())
        # MAC shown as its own label, not embedded in the dropdown value --
        # ttk.Combobox's popdown list width tracks the widget's own
        # configured width, not its longest value, so a MAC-suffixed entry
        # gets clipped in the dropdown itself (same real ttk limitation
        # already worked around for the target filter combo below).
        ttk.Label(iface_col, textvariable=self.adapter_mac_var, style="Muted.TLabel").grid(
            row=0, column=2, sticky=tk.W, padx=(6, 0))
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
        self.scan_btn = ttk.Button(container, text="Start Scanning", command=self._start_scan, style="Toolbar.Accent.TButton")
        stop_scan_btn = ttk.Button(container, text="Stop Scan", command=self._stop_scan, style="Toolbar.TButton")
        start_mon_btn = ttk.Button(container, text="Start Monitor", command=self._start_monitor, style="Toolbar.TButton")
        stop_mon_btn = ttk.Button(container, text="Stop Monitor", command=self._stop_monitor, style="Toolbar.TButton")
        wps_btn = ttk.Button(container, text="WPS Scan", command=self._open_wps_scan, style="Toolbar.TButton")
        unlock_btn = ttk.Button(container, text="Unlock", command=self._unlock_channel, style="Toolbar.TButton")
        # No toolbar monitor-status pill (removed per 2026-08-27 user
        # report -- monitor state still logs via _run_bg's own start/result
        # lines and the status bar, just not as a standing toolbar widget).

        self._toolbar_container = container
        self._toolbar_items = [
            iface_col, self.scan_btn, stop_scan_btn, start_mon_btn, stop_mon_btn, wps_btn, unlock_btn,
        ]
        self._toolbar_rows: list[ttk.Frame] = []
        self._toolbar_reflow_width = -1
        self._toolbar_reflowing = False
        container.bind("<Configure>", self._reflow_toolbar)
        self.root.after_idle(self._reflow_toolbar)


    def _reflow_toolbar(self, _event=None):
        # Re-entrancy guard: packing a new row frame into `container` fires
        # another <Configure> on `container` itself, and winfo_reqwidth()
        # below is enough to let Tk dispatch that queued event *during* this
        # same call -- without the guard that recursive call tears down
        # self._toolbar_rows mid-loop while the outer call is still packing
        # into them ("bad window path name", reproduced live 2026-08-28).
        if self._toolbar_reflowing:
            return
        container = self._toolbar_container
        width = container.winfo_width()
        if width <= 1 or width == self._toolbar_reflow_width:
            return
        self._toolbar_reflowing = True
        try:
            self._toolbar_reflow_width = width

            for row in self._toolbar_rows:
                row.destroy()
            self._toolbar_rows = []
            for item in self._toolbar_items:
                item.pack_forget()
                item.grid_forget()

            # Group items into rows by measured width first, then grid each
            # row's items with equal column weight so a short trailing row
            # (e.g. just "Unlock" alone) stretches to fill the row instead
            # of leaving a large blank gap (2026-08-28 user report: wrapping
            # fixed the clipping but left "wasted empty spaces").
            rows: list[list[tk.Widget]] = [[]]
            used = 0
            for item in self._toolbar_items:
                req = item.winfo_reqwidth() + 8
                if used + req > width and rows[-1]:
                    rows.append([])
                    used = 0
                rows[-1].append(item)
                used += req

            for row_items in rows:
                # Each row frame is a sibling of the toolbar items (all
                # children of `container`), placed via -in rather than true
                # reparenting. A freshly created sibling window stacks above
                # its older siblings by default, so the row's own opaque
                # background was painting straight over the already-existing
                # buttons inside it ("packed successfully" per logging, but
                # invisible on screen -- reproduced live 2026-08-28).
                # lower() fixes the stacking order.
                row = ttk.Frame(container, style="Toolbar.TFrame")
                row.pack(side=tk.TOP, fill=tk.X)
                row.lower()
                self._toolbar_rows.append(row)
                for col, item in enumerate(row_items):
                    row.columnconfigure(col, weight=1)
                    pad = (2, 10) if item is self._toolbar_items[0] else 4
                    item.grid(in_=row, row=0, column=col, sticky="ew", padx=pad, pady=2)
        finally:
            self._toolbar_reflowing = False

    # ------------------------------------------------------------------
    # Body: PanedWindow(target tree | Notebook(Target tab, Captures tab)) + log
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Body: PanedWindow(target tree | Notebook(Target tab, Captures tab)) + log
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
        # Top-level Notebook (Target tab | Captures tab) instead of one long
        # silent-scroll column (2026-08-27 reskin) -- that single column
        # buried Captures, and most of the Attacks list, below the fold with
        # no visible cue there was more to see (2026-08-28 user report:
        # "resizing makes hidden buttons appear that I was not aware of";
        # Captures could shrink to nothing at normal window heights). Tabs
        # give each one the *full* body height instead (2026-08-28 user
        # request, citing v1/n2-ng's own tabbed raw-log precedent).
        #
        # The Scanned Access Points list lives INSIDE the Target tab, not
        # beside the Notebook -- Captures work (managing/cracking files) has
        # no use for it, so keeping it always-visible just stole width from
        # the Captures button row/file table for no reason (2026-08-28 user
        # request: "make the captures tab open all the way to the left to
        # hide the scanned access points window"). It reappears automatically
        # when the Target tab is reselected, since it's that tab's own child,
        # not a separately-hidden widget.
        #
        # Log itself stays untabbed, always a full-width bottom strip (user
        # live-test note 2026-08-27: moving IT into a notebook tab hid it).
        body = ttk.Frame(self.root, padding=2)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(body)
        notebook.pack(fill=tk.BOTH, expand=True)

        target_tab = ttk.Frame(notebook)
        notebook.add(target_tab, text="Target")
        pane = ttk.PanedWindow(target_tab, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(target_tab)
        pane.add(left, weight=2)
        self._build_target_tree(left)

        right = ttk.Frame(target_tab)
        pane.add(right, weight=3)
        inner = self._make_scrollable(right)
        self._build_target_panel(inner)
        canvas, on_wheel = self._wheel_bind_target
        self._bind_wheel_recursive(inner, on_wheel)
        self._bind_wheel_recursive(canvas, on_wheel)

        captures_tab = ttk.Frame(notebook)
        notebook.add(captures_tab, text="Captures")
        self.captures_box = ttk.LabelFrame(captures_tab, text="Captures")
        self.captures_box.pack(fill=tk.BOTH, expand=True)
        self._build_captures_panel(self.captures_box)

        # Log stays a full-width bottom strip, always visible (user
        # live-test note 2026-08-27: moving it into a notebook tab hid it).
        self._build_log_pane(body)


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

        # Dropdown values are the short form (iface + vendor) only -- see
        # the MAC-label comment where adapter_combo is built for why the
        # MAC can't safely live inside a combobox value.
        displays = [self._iface_display_short(i) for i in ifaces]
        self._iface_display_to_name = dict(zip(displays, ifaces))
        self._iface_short_display = {i: self._iface_display_short(i) for i in ifaces}
        self.adapter_combo["values"] = displays
        self.iface_ap_combo["values"] = displays

        if ifaces and not self.adapter_var.get():
            self.adapter_var.set(ifaces[0])
        self._sync_iface_display(self.adapter_var, self.adapter_display_var)
        self._update_adapter_mac_label()

        saved_iface_ap = self.settings.get("iface_ap", "")
        if saved_iface_ap and saved_iface_ap in ifaces:
            self.iface_ap_var.set(saved_iface_ap)
        elif not self.iface_ap_var.get() or self.iface_ap_var.get() not in ifaces:
            # Rogue-AP workflows need a *second* interface distinct from the
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


    def _update_adapter_mac_label(self):
        """Refresh adapter_mac_var from the currently-selected adapter's MAC.
        Kept out of the combobox value itself -- see the label comment next
        to adapter_combo's construction."""
        from ..radio import RadioError, get_mac

        iface = self.adapter_var.get()
        try:
            self.adapter_mac_var.set(get_mac(iface) if iface else "")
        except RadioError:
            self.adapter_mac_var.set("")  # interface down/gone -- MAC just isn't shown


    def _on_adapter_selected(self):
        self.adapter_var.set(self._iface_display_to_name.get(self.adapter_display_var.get(), self.adapter_display_var.get()))
        self._sync_iface_display(self.adapter_var, self.adapter_display_var)
        self._update_adapter_mac_label()


    def _on_iface_ap_selected(self):
        self.iface_ap_var.set(self._iface_display_to_name.get(self.iface_ap_display_var.get(), self.iface_ap_display_var.get()))
        self._sync_iface_display(self.iface_ap_var, self.iface_ap_display_var)
        self._save_settings()


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
                self._log(f"optional tools not found (some Captures actions will report unavailable): {', '.join(opt_missing)}")
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
        try:
            self._about_logo_image = tk.PhotoImage(file=str(Path(__file__).parent / "assets" / "logo_about.png"))
            tk.Label(win, image=self._about_logo_image, bg=self.THEME["bg"]).pack(padx=32, pady=(24, 0))
        except tk.TclError:
            pass
        text = (
            f"ATWA-NG\nVersion {__version__}\n\n"
            "by KiMiGuel — INDEPENTEST LLC\n"
            "github.com/KiMiGuel\n"
            "indepentest.pro"
        )
        ttk.Label(win, text=text, justify=tk.CENTER, anchor=tk.CENTER).pack(padx=32, pady=(12, 12))
        ttk.Button(win, text="OK", command=win.destroy).pack(pady=(0, 16))
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{x}+{y}")


    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    def _choose_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist")
        if path:
            self.wordlist_var.set(path)

    # Curated subset of John's stock rule sections (see /etc/john/john.conf
    # [List.Rules:*]) -- not exhaustive, just the commonly-used ones. Free
    # text is still accepted for anything else defined there.
    _JOHN_RULE_PRESETS = ("None", "Wordlist", "best64", "Jumbo", "All", "hashcat")


    def _choose_john_rules(self):
        """Global setting (File menu, not per-dialog): which John --rules
        section every crack run uses, applied uniformly whether cracking
        starts from the Captures panel's quick buttons or the Crack
        Handshakes dialog -- one setting, everywhere John runs."""
        win = tk.Toplevel(self.root)
        win.title("Set John Ruleset")
        win.configure(bg=self.THEME["bg"])
        win.transient(self.root)
        win.resizable(False, False)

        ttk.Label(win, text="John --rules section (word-mangling rules applied to the wordlist):").pack(
            anchor=tk.W, padx=10, pady=(10, 4))
        var = tk.StringVar(value=self.john_rules_var.get() or "None")
        combo = ttk.Combobox(win, textvariable=var, values=self._JOHN_RULE_PRESETS, width=30)
        combo.pack(anchor=tk.W, padx=10, pady=(0, 4))
        ttk.Label(win, text="(or type any other section name from john.conf)",
                  style="Muted.TLabel").pack(anchor=tk.W, padx=10, pady=(0, 10))

        def apply_and_close():
            chosen = var.get().strip() or "None"
            self.john_rules_var.set("" if chosen.lower() == "none" else chosen)
            win.destroy()

        buttons = ttk.Frame(win)
        buttons.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(buttons, text="OK", command=apply_and_close, style="Accent.TButton").pack(side=tk.LEFT)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side=tk.LEFT, padx=6)


    def _choose_capture_dir(self):
        path = filedialog.askdirectory(title="Select capture folder")
        if path:
            self.capture_dir_var.set(path)
            self._refresh_captures()


    def _save_settings(self):
        self.settings.set("wordlist", self.wordlist_var.get())
        self.settings.set("john_rules", self.john_rules_var.get())
        self.settings.set("capture_dir", self.capture_dir_var.get())
        self.settings.set("adapter", self.adapter_var.get())
        self.settings.set("iface_ap", self.iface_ap_var.get())
        self.settings.set("security_filter", self.security_filter_var.get())
        self.settings.set("randomize_mac", self.randomize_mac_var.get())
        self.settings.set("sort_col", self._sort_col)
        self.settings.set("sort_reverse", self._sort_reverse)
        self.settings.set("hidden_columns", sorted(self.hidden_columns))
        self.settings.set("column_order", self.column_order)
        try:
            self.settings.save()
        except OSError as exc:
            self._log(f"could not save settings: {exc}")


    def _on_close(self):
        # Stop running work FIRST, before any radio teardown:
        # - auto-deauth listens to ITS OWN stop event (not self._stop_event),
        #   so it kept firing deauth bursts during set_managed_mode below and
        #   could re-flip the adapter to monitor AFTER it was restored --
        #   leaving the radio in the wrong state on exit;
        # - a crack subprocess runs in its own session (start_new_session)
        #   and nothing else signals it on shutdown, orphaning it on CPU.
        self._stop_attack()
        crack_proc = self._crack_proc_holder.get("proc")
        if crack_proc is not None and crack_proc.poll() is None:
            # _stop_attack escalates in a daemon thread with a 3s grace --
            # but the process exits right after root.destroy(), killing that
            # thread before SIGKILL. Finish it synchronously here; grace is
            # short because we are closing.
            from ..crack.john import terminate_tree

            try:
                terminate_tree(crack_proc, grace=1.0)
            except Exception:  # noqa: BLE001, S110 - shutdown cleanup is best-effort
                pass
        if self._auto_deauth_thread is not None:
            self._auto_deauth_thread.join(timeout=2.0)
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
        # (dwell defaults to 0.25s); 2s leaves comfortable margin.
        if self._scan_thread is not None:
            self._scan_thread.join(timeout=2.0)
        self._save_settings()
        if self.mon_iface and "demo" not in self.mon_iface:
            try:
                from ..radio import restart_network_manager, set_managed_mode

                iface = self.mon_iface
                set_managed_mode(iface, restore_mac=self._permanent_mac)
                # Best-effort, and after the mode restore: a restart on
                # exit is what stops the adapter being left unassociated.
                restart_network_manager(iface)
            except Exception:  # noqa: BLE001, S110 - shutdown cleanup must be best-effort
                pass
        self.root.destroy()


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
        self.mon_iface = "wlan0 (demo)"
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
