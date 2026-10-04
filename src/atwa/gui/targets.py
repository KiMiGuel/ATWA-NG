"""Target list and target detail panel: column handling, selection,
and channel lock.
"""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from ..scan import AccessPoint
from .layout import CHANNEL_LOCK_TIMEOUT, TARGET_COLUMNS, TARGET_STRETCH_COLUMN
from .state import GuiState
from .widgets import SignalGraph


class TargetsMixin(GuiState):

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
            # No command= here -- click-to-sort is driven entirely by
            # _on_tree_heading_press/_release below, alongside drag-to-
            # reorder, so there's exactly one source of truth for what a
            # heading press/release means instead of two competing ones.
            self.tree.heading(key, text=heading)
            # stretch=False on every column but TARGET_STRETCH_COLUMN: fixed
            # columns keep whatever width the user drags them to instead of
            # ttk auto-compressing them to fit the visible pane (2026-08-26
            # live-test note: columns weren't comfortably resizable/reachable
            # when narrower than total width) — but one column has to absorb
            # slack width or it just sits wasted while SSID truncates
            # (2026-08-28 user report).
            self.tree.column(key, width=width, minwidth=40, stretch=(key == TARGET_STRETCH_COLUMN))
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
        # Column headings drive both click-to-sort AND drag-to-reorder from
        # this one press/release pair (2026-09-08 user request for drag
        # reordering) -- deliberately NOT ttk's built-in heading command=
        # callback plus a separate drag binding, since the two would race:
        # ttk fires its own heading command on release regardless of
        # whether the press started there, so a real reorder-drag would
        # ALSO trigger a sort on the origin column. One handler, one
        # decision (same column released = click = sort; different column
        # = drag = reorder), no double-firing possible.
        self.tree.bind("<ButtonPress-1>", self._on_tree_heading_press, add="+")
        self.tree.bind("<ButtonRelease-1>", self._on_tree_heading_release, add="+")
        self._drag_press_col: str | None = None

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
        self.column_order: list[str] = list(self.settings.get("column_order", []))
        self._apply_column_visibility()

        # Row color by security (OPN/WEP/WPA/WPA2/WPA3).
        self.tree.tag_configure("open", foreground="#888888")
        self.tree.tag_configure("wep", foreground=self.THEME["error"])
        self.tree.tag_configure("wpa", foreground=self.THEME["warn"])
        self.tree.tag_configure("wpa2", foreground="#ffffff")
        self.tree.tag_configure("wpa3", foreground=self.THEME["info"])
        self.tree.tag_configure("transition", foreground="#cc88ff")
        self.tree.tag_configure("owe", foreground="#ff9500")
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
        self.client_tree.tag_configure("row_even", background=self.THEME["tree_bg"], foreground=self.THEME["fg"])
        self.client_tree.tag_configure("row_odd", background=self.THEME["tree_band"], foreground=self.THEME["fg"])
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
        # Smart/OMNI/Dragonblood pulled out of this grid (2026-09-12 user
        # request) into their own full-width rows below it -- besides the
        # requested visual promotion, it also fixes a leftover blank grid
        # cell: an odd number of entries in a 2-column grid leaves the last
        # row alone with an empty neighbor. The grid below holds 14 entries
        # (7 even rows), and CHAOS was added to the full-width chain group
        # rather than the grid so it stays even (2026-09-26).
        buttons = [
            ("Deauth All Clients", self._attack_deauth_all, "TButton"),
            ("Deauth Selected Client", self._attack_deauth_client, "TButton"),
            ("PMKID Attack (Clientless)", self._attack_pmkid, "TButton"),
            ("Handshake Capture", self._attack_handshake, "TButton"),
            ("WEP Attack", self._attack_wep, "TButton"),
            ("WEP Caffe Latte", self._attack_caffe_latte, "TButton"),
            ("WEP Hirte", self._attack_hirte, "TButton"),
            ("WEP Chopchop", self._attack_chopchop, "TButton"),
            ("WPS Null-PIN", self._attack_wps_null_pin, "TButton"),
            ("WPS Pixie-Dust", self._attack_wps_pixie, "TButton"),
            ("WPS Bruteforce (experimental)", self._attack_wps_bruteforce, "TButton"),
            "rogue_ap_menu",
            ("Online Password Guess", self._attack_online_guess, "TButton"),
            "flood_menu",
        ]
        # 2-column grid instead of one-per-row: halves the panel's total
        # height, which is what was pushing WPS/Rogue-AP/Online-Guess (and
        # Captures below them) off the bottom of the window at normal sizes
        # (2026-08-28 user report: "resizing makes hidden buttons appear").
        attack_grid = ttk.Frame(attacks_box)
        attack_grid.pack(fill=tk.X, padx=2, pady=(0, 1))
        attack_grid.columnconfigure(0, weight=1)
        attack_grid.columnconfigure(1, weight=1)
        self.attack_buttons: list[ttk.Button] = []
        for i, entry in enumerate(buttons):
            if entry == "rogue_ap_menu":
                # Portal-free rogue-AP variants share one compact menu.
                rogue_ap_menu = tk.Menu(attack_grid, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
                rogue_ap_menu.add_command(label="Downgrade Twin", command=self._attack_downgrade_twin)
                rogue_ap_menu.add_command(label="OWE Downgrade", command=self._attack_owe_downgrade)
                b = ttk.Menubutton(attack_grid, text="Rogue AP ▾", menu=rogue_ap_menu, style="TMenubutton")
                b.rogue_ap_menu = rogue_ap_menu  # keep the Menu alive with the widget
            elif entry == "flood_menu":
                # Five protocol-disruption/DoS attacks (v2.4) collapsed into
                # one dropdown, same reasoning as the Rogue AP menu above -- each is
                # a one-off action against the current target, not worth a
                # full grid cell of its own.
                flood_menu = tk.Menu(attack_grid, tearoff=0, bg=self.THEME["panel"], fg=self.THEME["fg"])
                flood_menu.add_command(label="CSA Spoof (channel redirect)", command=self._attack_csa_spoof)
                flood_menu.add_command(label="EAPOL-Start Flood", command=self._attack_eapol_flood)
                flood_menu.add_command(label="Auth Flood", command=self._attack_auth_flood)
                flood_menu.add_command(label="Beacon Flood", command=self._attack_beacon_flood)
                flood_menu.add_command(label="TKIP MIC Flood", command=self._attack_tkip_mic_flood)
                b = ttk.Menubutton(attack_grid, text="Flood / DoS ▾", menu=flood_menu, style="TMenubutton")
                b.flood_menu = flood_menu  # keep the Menu alive with the widget
            else:
                label, cmd, style = entry
                b = ttk.Button(attack_grid, text=label, command=cmd, style=style)
            b.grid(row=i // 2, column=i % 2, sticky="ew", padx=2, pady=1)
            self.attack_buttons.append(b)

        # Smart/OMNI/CHAOS promoted to full-width rows below the grid, same
        # width as Dragonblood/PINCER (2026-09-12 user request) -- these are
        # the "run a whole chain" attacks, not one-off actions, so they get
        # the same visual weight as PINCER rather than sharing a half-width
        # grid cell with e.g. "WEP Chopchop".
        for label, cmd in (
            ("Smart Attack (Auto)", self._attack_smart),
            ("OMNI Attack (All Stages)", self._attack_omni),
            ("CHAOS Flood (All Vectors)", self._attack_chaos),
        ):
            b = ttk.Button(attacks_box, text=label, command=cmd, style="Accent.TButton")
            b.pack(fill=tk.X, padx=4, pady=1)
            self.attack_buttons.append(b)

        # PINCER kept out of self.attack_buttons: it needs a second enable
        # condition (a detected dual-Alfa pair) that _set_busy()'s blanket
        # NORMAL-on-idle reset would otherwise clobber -- see _set_busy()
        # and _refresh_adapters() for where its state actually gets set.
        # Styled to match Smart/OMNI's accent color (2026-09-12 user
        # request) with a bigger font + a pincer emoji, same treatment as
        # Dragonblood's own icon+color identity below.
        self.pincer_button = ttk.Button(
            attacks_box, text="🦀 PINCER (Dual-Alfa)", command=self._attack_pincer, state=tk.DISABLED,
            style="PincerAccent.TButton",
        )
        self.pincer_button.pack(fill=tk.X, padx=4, pady=1)

        # Dragonblood last (2026-09-12 user request: swap with PINCER so
        # Dragonblood sits at the very bottom) -- it's experimental, so it
        # gets the final slot rather than sharing the grid with routine
        # actions.
        dragonblood_btn = ttk.Button(
            attacks_box, text="🩸 Dragonblood (unverified)", command=self._attack_dragonblood, style="Blood.TButton",
        )
        dragonblood_btn.pack(fill=tk.X, padx=4, pady=(1, 4))
        self.attack_buttons.append(dragonblood_btn)


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
        # list(...) snapshots self.aps before iterating -- the scan thread
        # adds new APs to this same dict concurrently, and iterating the
        # live dict directly raised "dictionary changed size during
        # iteration" here (confirmed live, 2026-08-28).
        rows = [ap for ap in list(self.aps.values()) if self._matches_security_filter(ap)]

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
        self._autosize_target_columns()


    def _autosize_target_columns(self):
        """Column width = actual longest rendered value (header or any
        current row), not a hardcoded guess -- fixes BSSID needing a manual
        drag every time to stop clipping its last couple characters, and CH
        sitting on wasted space while other columns are tight (2026-09-08
        user report). Recomputed on every render since content changes
        (new APs discovered, SSIDs resolved from hidden to real)."""
        font = self.fonts["mono"]
        pad = 24  # heading sort-arrow (▲/▼ + space) plus Treeview's own cell padding
        for key, heading, _default_width in TARGET_COLUMNS:
            widest = font.measure(f"{heading} ▼")  # account for the sort-arrow suffix even when not currently sorted by this column
            for iid in self.tree.get_children():
                widest = max(widest, font.measure(str(self.tree.set(iid, key))))
            self.tree.column(key, width=widest + pad)


    def _on_tree_heading_press(self, event):
        region = self.tree.identify_region(event.x, event.y)
        self._drag_press_col = self.tree.identify_column(event.x) if region == "heading" else None


    def _on_tree_heading_release(self, event):
        """Same column released as pressed -> plain click -> sort (what
        ttk's own heading command= used to do). Different column -> the
        user dragged one heading onto another -> swap their display order
        instead. See the binding-site comment for why both live in one
        handler rather than ttk's command= plus a separate drag binding."""
        pressed = self._drag_press_col
        self._drag_press_col = None
        region = self.tree.identify_region(event.x, event.y)
        if pressed is None or region != "heading":
            return
        released = self.tree.identify_column(event.x)
        if released == pressed:
            col = self._displaycolumn_to_key(pressed)
            if col:
                self._on_target_heading_click(col)
        else:
            self._reorder_columns(pressed, released)


    def _displaycolumn_to_key(self, display_id: str) -> str | None:
        """identify_column() returns '#N' (1-indexed position among
        currently VISIBLE columns) -- map that back to a real column key."""
        try:
            idx = int(display_id.replace("#", "")) - 1
        except ValueError:
            return None
        displaycols = list(self.tree["displaycolumns"])
        return displaycols[idx] if 0 <= idx < len(displaycols) else None


    def _reorder_columns(self, from_display_id: str, to_display_id: str):
        """Swap two columns' positions (drag one heading onto another).
        Persisted the same way hidden_columns already is, via
        _save_settings()."""
        displaycols = list(self.tree["displaycolumns"])
        from_key = self._displaycolumn_to_key(from_display_id)
        to_key = self._displaycolumn_to_key(to_display_id)
        if from_key is None or to_key is None:
            return
        from_idx, to_idx = displaycols.index(from_key), displaycols.index(to_key)
        displaycols[from_idx], displaycols[to_idx] = displaycols[to_idx], displaycols[from_idx]
        self.tree["displaycolumns"] = displaycols
        self.column_order = displaycols


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
        menu.add_command(
            label="Auto-Deauth This Client",
            command=lambda client=row: self._start_client_auto_deauth(client),
        )
        menu.add_command(label="Copy MAC", command=lambda: self._copy_to_clipboard(row))
        menu.tk_popup(event.x_root, event.y_root)


    def _copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"Copied {text} to clipboard")


    def _apply_column_visibility(self):
        """displaycolumns, not width=0 — a zero-width column is still a
        clickable sliver in ttk.Treeview, this actually removes it.

        Order comes from self.column_order (user drag-reordering, see
        _reorder_columns) with any column missing from it (never dragged
        yet, or newly added to TARGET_COLUMNS in a future version) appended
        at its default TARGET_COLUMNS position -- so a column can never
        silently disappear just because it's absent from a saved order."""
        order = self.column_order + [key for key, _, _ in TARGET_COLUMNS if key not in self.column_order]
        visible = [key for key in order if key not in self.hidden_columns]
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
            f"Manufacturer: {ap.manufacturer or '-'}\n"
            f"Channel: {ap.channel or '-'}\n"
            f"Security: {ap.security or '-'}\n"
            f"PMF: {ap.pmf or '-'}\n"
            f"Signal: {ap.signal if ap.signal is not None else '-'} dBm\n"
            f"RX quality: {ap.rx_quality}%\n"
            f"Clients seen: {len(ap.clients)}"
            + (f"\nPMKID (passively sniffed): {ap.pmkid}" if ap.pmkid else "")
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
        current_set = set(current_ids)
        new_set = set(ap.clients)
        if current_set == new_set:
            for mac in current_ids:
                signal = ap.client_signal.get(mac)
                self.client_tree.item(mac, values=(mac, signal if signal is not None else "-"))
        else:
            # Re-sorting the whole list alphabetically on every rebuild (the
            # old behavior) relocated existing rows on every client-set
            # change -- on a busy AP that's most scan ticks. A click and a
            # rebuild landing close together then raced: the row under the
            # cursor when the click registered wasn't necessarily the row
            # the user saw, and one MAC would appear permanently "stuck"
            # selected (2026-09-13 live-test report). Keep existing rows in
            # their existing order -- never relocate a row once inserted --
            # and only append newly-seen clients at the end.
            prev_selection = self.client_tree.selection()
            kept_ids = [mac for mac in current_ids if mac in new_set]
            added_ids = sorted(mac for mac in new_set if mac not in current_set)
            new_ids = kept_ids + added_ids
            self.client_tree.delete(*current_ids)
            for i, mac in enumerate(new_ids):
                signal = ap.client_signal.get(mac)
                band_tag = "row_even" if i % 2 == 0 else "row_odd"
                self.client_tree.insert(
                    "", tk.END, iid=mac, values=(mac, signal if signal is not None else "-"), tags=(band_tag,),
                )
            still_present = [mac for mac in prev_selection if mac in new_set]
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


    def _start_lock_capture(self, ap: AccessPoint):
        """Native AsyncSniffer-backed capture (capture.lock.LockCapture),
        restricted to ap's bssid on the already-locked channel, writing
        continuously to disk. Stopped by _unlock_channel/_stop_lock_capture."""
        assert self.mon_iface is not None
        self._stop_lock_capture()
        import time as _time

        from ..capture.lock import LockCapture
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
        if self._busy:
            # A row click while an attack runs must stay passive. Routing it
            # through _run_bg popped the "Another background operation..."
            # warning at the operator for doing nothing, and
            # _start_lock_capture still fired on a channel the refused
            # ensure_channel work never set -- lock state, lock capture and
            # radio channel drifted apart. The hopper is paused during busy
            # and _scan_channels above means it resumes on THIS channel when
            # the attack ends.
            self._log(f"channel switch deferred until the running attack ends ({ap.bssid})")
        elif self.mon_iface and "demo" not in self.mon_iface:
            def work():
                from ..radio import ensure_channel

                ensure_channel(self.mon_iface, ap.channel)
                return f"channel {ap.channel}"

            self._run_bg(f"Set channel {ap.channel}", work)
            # A client-less target can never yield a handshake (nothing to
            # deauth/reconnect), so a continuous lock capture there is pure
            # write-and-discard -- and single-click locking means every row
            # glanced at while browsing starts one. Most of the folder-
            # filling clutter was exactly this: dozens of near-empty
            # lock_*.pcap files across networks the user never actually
            # attacked, just scrolled past. Skip starting the capture
            # entirely when no clients are known yet; if one shows up
            # later while still locked, re-locking (e.g. Unlock + relock,
            # or double-click) will pick it up.
            if ap.clients:
                self._start_lock_capture(ap)
            else:
                self._log(f"no clients seen yet on {ap.bssid} — skipping lock capture (nothing to record)")


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


    def _watch_capture_size(self, path, stop_event: threading.Event):
        """A live-growing capture-size readout (0 B -> ... KB) next to
        the signal graph, confirming data is actually landing on disk
        during a capture — not just that an attack is 'running'."""
        import time as _time

        p = Path(path)
        while not stop_event.is_set():
            try:
                size = p.stat().st_size if p.exists() else 0
            except OSError:
                size = 0
            self._queue.put(("capture_size", size))
            _time.sleep(1)
        self._queue.put(("capture_size", None))
