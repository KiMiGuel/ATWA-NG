"""Captures tab: the capture tree plus inspect/convert/fix/merge/crack
and per-target cleanup.
"""

from __future__ import annotations

import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from .layout import CAPTURE_COLUMNS, CAPTURE_STRETCH_COLUMN
from .state import GuiState


class CapturesMixin(GuiState):

    def _build_captures_panel(self, parent):
        opts_row = ttk.Frame(parent)
        opts_row.pack(fill=tk.X, padx=4, pady=(4, 6))
        ttk.Label(opts_row, text="Capture dir:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.capture_dir_var, width=40).grid(row=0, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_capture_dir).grid(row=0, column=2)
        ttk.Label(opts_row, text="Wordlist:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opts_row, textvariable=self.wordlist_var, width=40).grid(row=1, column=1, sticky=tk.EW, padx=6)
        ttk.Button(opts_row, text="Browse", command=self._choose_wordlist).grid(row=1, column=2)
        # minsize floor -- without it, grid shrinks this column straight to
        # 0 (entry fully invisible, label butted against Browse) once the
        # right pane gets narrow, instead of just truncating the text
        # (2026-08-28 user report: fields vanishing on resize).
        opts_row.columnconfigure(1, weight=1, minsize=100)

        # Crack w/ John and Crack w/ Aircrack pulled out of the action grid
        # below into their own full-width row -- these are THE two primary
        # crack actions (the folder-picker dialog that used to occupy the
        # prominent accent-button slot was removed as redundant with this
        # panel's own file list), so they get the visual weight instead of
        # being sized identically to Refresh/Copy Path/etc.
        crack_row = ttk.Frame(parent)
        crack_row.pack(fill=tk.X, padx=4, pady=(0, 4))
        john_btn = ttk.Button(crack_row, text="Crack w/ John", command=self._capture_crack_john,
                              style="Accent.TButton")
        john_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        aircrack_btn = ttk.Button(crack_row, text="Crack w/ Aircrack", command=self._capture_crack_aircrack,
                                  style="Accent.TButton")
        aircrack_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
        self.capture_buttons.extend((john_btn, aircrack_btn))

        # Wrapping grid, not a single pack(side=LEFT) row -- 9 buttons in one
        # unwrapped row ran off the right edge with no way to reach the last
        # few short of the Captures menu (2026-08-28 user report: "captures
        # tab still has hidden buttons"). Fixed column count wraps them onto
        # as many rows as needed instead of however wide the window happens
        # to be.
        actions = ttk.Frame(parent)
        actions.pack(fill=tk.X, padx=4, pady=(0, 4))
        action_defs = [
            ("Refresh", self._refresh_captures, "TButton"),
            ("Inspect", self._capture_inspect, "TButton"),
            ("Inspect All", self._capture_inspect_all, "TButton"),
            ("Convert to 22000", self._capture_convert, "TButton"),
            ("Fix", self._capture_fix, "TButton"),
            ("Merge (2+)", self._capture_merge, "TButton"),
            ("Crack Selected", self._capture_crack, "TButton"),
            ("Copy Path", self._capture_copy_path, "TButton"),
            ("Benchmark (John)", self._capture_benchmark_john, "TButton"),
            ("Stop Cracking", self._stop_cracking, "Danger.TButton"),
            ("Cleanup Handshakes...", self._capture_cleanup, "Danger.TButton"),
        ]
        # 6 per row: 11 buttons -> 1 full row + a 5-button last row, which
        # the last-row-span logic below stretches its last button across
        # the remaining column (see that logic's own comment for why a
        # short last row needs it). Crack w/ John and Crack w/ Aircrack
        # aren't in this grid -- they get their own full-width row above,
        # see crack_row.
        actions_per_row = 6
        n = len(action_defs)
        for col in range(actions_per_row):
            actions.columnconfigure(col, weight=1)
        for i, (label, cmd, style) in enumerate(action_defs):
            row, col = divmod(i, actions_per_row)
            # Last button spans the remaining columns when its row is short
            # a full set -- otherwise it sits at its natural width with dead
            # space stretching out past it instead of reaching the row's
            # right edge like every full row does (2026-08-28 user report:
            # "wasted space after the red crack button").
            row_is_short = (n - row * actions_per_row) < actions_per_row
            span = actions_per_row - col if (i == n - 1 and row_is_short) else 1
            btn = ttk.Button(actions, text=label, command=cmd, style=style)
            btn.grid(row=row, column=col, columnspan=span, sticky="ew", padx=2, pady=2)
            if label != "Stop Cracking":
                self.capture_buttons.append(btn)

        # Horizontal scrollbar packed before tree_frame claims the bottom
        # strip first (same ordering as the target tree above) -- packing
        # it after would leave it no space once tree_frame's fill=BOTH/
        # expand=True already claimed everything.
        capture_hsb = ttk.Scrollbar(parent, orient=tk.HORIZONTAL)
        capture_hsb.pack(fill=tk.X, padx=4)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        cols = [c[0] for c in CAPTURE_COLUMNS]
        self.capture_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended", height=6)
        for key, heading, width in CAPTURE_COLUMNS:
            self.capture_tree.heading(key, text=heading)
            # stretch=False on every column but CAPTURE_STRETCH_COLUMN: same
            # fix as the target tree -- without it ttk auto-compresses every
            # column to fit the visible width instead of leaving them at
            # their set width with a scrollbar, which is what was mangling
            # "Kind"/"Size" headers into "Kin"/"Siz" on a narrow window
            # (2026-08-28 user report). Path still stretches so slack width
            # goes somewhere useful instead of sitting wasted.
            self.capture_tree.column(key, width=width, minwidth=40, stretch=(key == CAPTURE_STRETCH_COLUMN))
        # "bright" (white), not the standard blue body-text color -- same
        # reasoning as the crack dialog's output Text widget (2026-08-28
        # user report: "the captures list is STILL BLUE COLOR when it needs
        # to be WHITE").
        self.capture_tree.tag_configure("row_even", background=self.THEME["tree_bg"], foreground=self.THEME["bright"])
        self.capture_tree.tag_configure("row_odd", background=self.THEME["tree_band"], foreground=self.THEME["bright"])
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.capture_tree.yview)
        capture_hsb.configure(command=self.capture_tree.xview)
        self.capture_tree.configure(yscrollcommand=vsb.set, xscrollcommand=capture_hsb.set)
        self.capture_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.capture_tree.bind("<Button-3>", self._on_capture_right_click)

        # Own dedicated scroll, not the outer page's (2026-08-27 user
        # report: "the handshakes box needs its own scroll bars") --
        # naturally isolated from the Attacks pane's wheel-bind now that
        # Captures lives in its own PanedWindow pane (2026-08-28 reskin),
        # not inside the Attacks pane's scrollable canvas.
        def on_capture_wheel(event):
            if event.num == 5 or event.delta < 0:
                self.capture_tree.yview_scroll(1, "units")
            elif event.num == 4 or event.delta > 0:
                self.capture_tree.yview_scroll(-1, "units")
        self._bind_wheel_recursive(parent, on_capture_wheel)

        self.root.after(50, self._refresh_captures)


    # ------------------------------------------------------------------
    # Captures tab
    # ------------------------------------------------------------------
    def _capture_files(self, root: str):
        """List capture files under ``root`` (a directory). The caller
        resolves capture_dir_var ON THE Tk THREAD and passes the value in:
        reading a Tk var from this function's usual worker thread is the
        same cross-thread Tcl access a .set() would be."""
        from pathlib import Path

        root_path = Path(root)
        if not root_path.exists():
            return []
        suffixes = {".cap", ".pcap", ".pcapng", ".22000"}
        files = []
        for path in root_path.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append((path, stat.st_size, stat.st_mtime))
        return sorted(files, key=lambda item: item[2], reverse=True)


    def _refresh_captures(self):
        """The scan (_capture_files' rglob + stat over the whole capture
        tree) can take a long time on a large/deep directory — running it
        synchronously on the Tk thread froze the entire GUI (2026-08-28
        user report: switching capture dir "completely freezes" it).
        Walk off-thread, populate the tree once the listing comes back."""
        if self._captures_refreshing:
            return
        self._captures_refreshing = True
        capture_root = self.capture_dir_var.get()  # Tk-thread read, value passed down

        def work():
            try:
                files = self._capture_files(capture_root)
            except Exception:  # noqa: BLE001 - never let a bad dir kill the thread silently
                files = []
            self._queue.put(("captures_ready", files))

        threading.Thread(target=work, daemon=True).start()


    def _populate_capture_tree(self, files: list):
        self._captures_refreshing = False
        new_ids = {str(path) for path, _size, _mtime in files}
        for iid in set(self.capture_tree.get_children()) - new_ids:
            self.capture_tree.delete(iid)
        for i, (path, size, _mtime) in enumerate(files):
            size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB" if size < 1024 ** 2 else f"{size / 1024 ** 2:.1f} MB"
            kind = "hash" if path.suffix.lower() == ".22000" else "capture"
            band_tag = "row_even" if i % 2 == 0 else "row_odd"
            iid = str(path)
            values = (path.name, kind, size_str, str(path))
            if self.capture_tree.exists(iid):
                if self.capture_tree.item(iid, "values") != values:
                    self.capture_tree.item(iid, values=values)
                self.capture_tree.item(iid, tags=(band_tag,))
                self.capture_tree.move(iid, "", i)
            else:
                self.capture_tree.insert(
                    "", tk.END, iid=iid, values=values, tags=(band_tag,),
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


    def _inspect_hash_capture(self, path) -> tuple[str, bool]:
        pmkid = handshake = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("WPA*01*"):
                    pmkid += 1
                elif line.startswith("WPA*02*"):
                    handshake += 1
        return f"{pmkid} PMKID line(s), {handshake} handshake line(s)", not (pmkid or handshake)


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
                    desc, _empty = self._inspect_hash_capture(path)
                    lines.append(f"{path.name}: {desc}")
                else:
                    lines.append(f"{path.name}: {self._inspect_capture(path)}")
            self._queue.put(("info", "\n".join(lines)))
            return "inspected"

        self._run_capture_task("Inspect capture(s)", work)


    def _inspect_capture(self, path) -> str:
        from scapy.utils import PcapReader

        from ..attacks.handshake import HandshakeCapture, _classify
        from ..eapol.pmkid import extract_pmkid
        from ..frames.craft import is_eapol

        cap = HandshakeCapture()
        pmkid_found = False
        packet_count = 0
        try:
            # Stream one packet at a time. rdpcap() builds a complete
            # Scapy PacketList, which made Inspect All's RAM usage scale
            # with the largest capture instead of staying bounded.
            with PcapReader(str(path)) as packets:
                for pkt in packets:
                    packet_count += 1
                    if is_eapol(pkt) and extract_pmkid(bytes(pkt)):
                        pmkid_found = True
                    msg_no = _classify(pkt)
                    if msg_no is not None and getattr(pkt, "addr3", None) and getattr(pkt, "addr1", None):
                        ap, client = pkt.addr3, pkt.addr1 if msg_no % 2 == 1 else pkt.addr2
                        cap.add(ap, client, msg_no)
        except Exception as exc:  # noqa: BLE001 - capture parse failures are reported, not fatal
            return f"could not parse ({exc})"
        statuses = [cap.status(a, c).value for a, c in cap.messages]
        parts = [f"{packet_count} packets"]
        if pmkid_found:
            parts.append("PMKID present")
        usable_statuses = [status for status in statuses if status in {"challenge", "authorized"}]
        if usable_statuses:
            parts.append(f"handshake pairs={statuses}")
        if not pmkid_found and not usable_statuses:
            parts.append("no PMKID/handshake material found")
        return ", ".join(parts)


    def _capture_inspect_all(self):
        paths = [self.capture_tree.set(iid, "path") for iid in self.capture_tree.get_children()]
        if not paths:
            messagebox.showinfo("ATWA-NG", "No captures to inspect.")
            return

        def work():
            from pathlib import Path

            lines, unreadable, delete_candidates = [], [], []
            for index, p in enumerate(paths, 1):
                path = Path(p)
                self._progress_fn(f"Inspecting {index}/{len(paths)}: {path.name}")
                if path.suffix.lower() == ".22000":
                    desc, empty = self._inspect_hash_capture(path)
                    lines.append(f"{path.name}: {desc}")
                    if empty:
                        delete_candidates.append(p)
                else:
                    # A live channel-lock capture is intentionally incomplete;
                    # never classify or delete it while the writer is active.
                    if path.name.startswith("lock_") and self._lock_capture_proc is not None:
                        lines.append(f"{path.name}: active channel-lock capture; skipped")
                        continue
                    desc = self._inspect_capture(path)
                    lines.append(f"{path.name}: {desc}")
                    if "could not parse" in desc:
                        unreadable.append(p)
                    elif "no PMKID/handshake material found" in desc:
                        delete_candidates.append(p)

            repaired, repair_failed, repair_errors = [], [], []
            if unreadable:
                from ..crack.convert import RepairUnavailableError, fix_capture

                for index, p in enumerate(unreadable, 1):
                    self._progress_fn(f"Repairing {index}/{len(unreadable)}: {Path(p).name}")
                    try:
                        out = fix_capture(p)
                    except RepairUnavailableError as exc:
                        # Do not delete when the repair tool itself is absent;
                        # that is not evidence that the capture is unusable.
                        repair_errors.append(f"{Path(p).name}: {exc}")
                    except (RuntimeError, OSError) as exc:
                        repair_failed.append(p)
                        repair_errors.append(f"{Path(p).name}: {exc}")
                    else:
                        repaired.append((p, out))
                        try:
                            Path(p).unlink()
                        except OSError as exc:
                            repair_errors.append(f"{Path(p).name}: repaired but original could not be deleted ({exc})")
                        else:
                            delete_candidates.append(p)
                        lines.append(f"{Path(p).name}: repaired -> {out}")
                lines.append(
                    f"Repair step: {len(repaired)} fixed, "
                    f"{len(repair_failed)} unrepairable, {len(unreadable) - len(repaired)} not processed"
                )
                for error in repair_errors:
                    lines.append(f"Repair failed: {error}")

            # NO unlink here. Deletion is a separate, reviewed step (see
            # _on_inspect_all_done): "no PMKID/handshake material" is a
            # WPA-only lens -- a WEP capture, a probe survey or a beacon
            # set reads exactly the same way -- and this button is named
            # "Inspect", not "Delete". Auto-unlinking here erased real
            # evidence before the result dialog even opened.
            return (lines, repaired, list(dict.fromkeys(delete_candidates)))

        self._run_capture_task("Inspect all captures", work, result_kind="inspect_all_done")


    def _on_inspect_all_done(self, payload):
        lines, repaired, candidates = payload
        self._show_scroll_dialog("Inspect All", "\n".join(lines))
        if candidates:
            names = "\n".join(Path(p).name for p in candidates)
            choice = self._show_scroll_dialog(
                "Delete captures without WPA material?",
                f"{len(candidates)} file(s) contain no PMKID/handshake material:\n\n"
                f"{names}\n\n"
                "Warning: this test only understands WPA -- WEP captures, probe "
                "surveys and beacon sets look the same. Only delete files you do "
                "not need. This cannot be undone.",
                buttons=("Delete", "Keep"),
            )
            if choice == "Delete":
                self._delete_unusable_captures(candidates)
        if repaired:
            self._refresh_captures()


    def _delete_unusable_captures(self, paths: list[str]) -> None:
        """Second half of Inspect All: unlink only what the operator just
        reviewed and explicitly confirmed."""

        def work():
            deleted, errors = [], []
            for p in dict.fromkeys(paths):
                try:
                    Path(p).unlink()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    errors.append(f"{Path(p).name}: {exc}")
                else:
                    deleted.append(p)
            for error in errors:
                self._progress_fn(f"delete failed: {error}")
            self._progress_fn(f"deleted {len(deleted)} capture(s), {len(errors)} error(s)")
            self._queue.put(("ui", self._refresh_captures))
            return f"{len(deleted)} unusable capture(s) deleted"

        self._run_capture_task("Delete unusable captures", work)


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
            self._queue.put(("ui", self._refresh_captures))
            return "converted"

        self._run_capture_task("Convert to 22000", work)


    def _capture_fix(self):
        paths = self._selected_capture_paths()
        if not paths:
            messagebox.showwarning("ATWA-NG", "Select a capture to fix first.")
            return
        from ..crack.convert import fix_capture

        def work():
            outputs = [fix_capture(p) for p in paths]
            self._queue.put(("info", "Fixed:\n" + "\n".join(outputs)))
            self._queue.put(("ui", self._refresh_captures))
            return "fixed"

        self._run_capture_task("Fix capture(s)", work)


    def _capture_merge(self):
        paths = self._selected_capture_paths()
        if len(paths) < 2:
            messagebox.showwarning("ATWA-NG", "Select at least two captures to merge.")
            return
        from ..crack.convert import merge_captures
        from ..storage import bssids_from_paths

        if any(not p.lower().endswith((".cap", ".pcap", ".pcapng")) for p in paths):
            messagebox.showwarning("ATWA-NG", "Merge accepts raw .cap/.pcap/.pcapng captures only, not .22000 files.")
            return
        bssids = bssids_from_paths(paths)
        if len(bssids) != 1:
            messagebox.showwarning(
                "ATWA-NG",
                "Merge captures from one BSSID at a time. A file containing multiple APs cannot be cracked safely.",
            )
            return
        bssid = next(iter(bssids))

        def work():
            from pathlib import Path

            suffix = Path(paths[0]).suffix
            out = merge_captures(
                paths,
                output_dir=Path(paths[0]).parent,
                output_name=f"capture_{bssid.replace(':', '-')}.merged{suffix}",
            )
            self._queue.put(("info", f"Merged into:\n{out}"))
            self._queue.put(("ui", self._refresh_captures))
            return out

        self._run_capture_task("Merge captures", work)


    def _capture_benchmark_john(self):
        """Real per-machine John speed (candidates/sec) via John's own
        --test self-benchmark -- no hashfile/wordlist needed, just the
        format. No --fork: John rejects --test combined with --fork."""
        from ..crack.john import JohnCracker, JohnUnavailableError

        def work():
            try:
                cracker = JohnCracker()
            except JohnUnavailableError as exc:
                return str(exc)
            result = cracker.benchmark()
            self._queue.put(("info", result))
            return "done"

        self._run_capture_task("Benchmark John", work)


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
        rows = [ap for ap in list(self.aps.values()) if ap.wps]  # list() snapshot: scan thread mutates self.aps concurrently
        rows.sort(key=lambda ap: ap.signal if ap.signal is not None else -999, reverse=True)
        for ap in rows:
            tree.insert("", tk.END, iid=ap.bssid, values=(
                ap.bssid, ap.channel or "-", ap.signal if ap.signal is not None else "-", ap.wps,
                ap.wps_manufacturer or "-", ap.wps_model_name or "-", ap.ssid or "<hidden>",
            ))


    def _capture_crack(self):
        """Crack the selected file(s): .22000 -> John, .cap/.pcap/.pcapng ->
        aircrack-ng (simpler for a single known target, per user request —
        needs one BSSID, derived from the capture path)."""
        selected = self._selected_capture_paths()
        hash_paths = [p for p in selected if p.lower().endswith(".22000")]
        cap_paths = [p for p in selected if p.lower().endswith((".cap", ".pcap", ".pcapng"))]
        if not hash_paths and not cap_paths:
            messagebox.showwarning("ATWA-NG", "Select one or more .22000 hash files or capture files first.")
            return
        if hash_paths and cap_paths:
            messagebox.showwarning("ATWA-NG", "Select either hash files or raw captures, not both. Use the backend button for a mixed selection.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return

        if hash_paths:
            self._crack_with_john(hash_paths, wordlist)
        else:
            self._crack_with_aircrack(cap_paths, wordlist)


    def _crack_with_john(self, paths: list[str], wordlist: str, cap_paths: list[str] | None = None):
        """cap_paths (optional): raw .cap/.pcap/.pcapng files to convert to
        22000 first, for the quick 'Crack w/ John' button which accepts
        either hash or capture files straight from the Captures selection."""
        from ..crack.convert import merge_22000_files
        from ..crack.john import JohnCracker, JohnUnavailableError
        from ..storage import bssids_from_paths, unique_path

        # Tk-thread reads; the worker below must not touch Tk vars.
        capture_root = self.capture_dir_var.get()
        john_rules = self.john_rules_var.get()

        def work():
            from pathlib import Path

            from ..crack.convert import cap_to_22000

            all_paths = list(paths)
            for cap in cap_paths or []:
                out = unique_path(Path(f"{cap}.22000"))
                cap_to_22000(cap, str(out))
                all_paths.append(str(out))
            hashfile = all_paths[0]
            if len(all_paths) > 1:
                merged_lines = merge_22000_files(all_paths)
                bssids = bssids_from_paths(all_paths)
                bssid_label = next(iter(bssids)).replace(":", "-") if len(bssids) == 1 else "unknown-bssid"
                output_dir = Path(capture_root)
                output_dir.mkdir(parents=True, exist_ok=True)
                hashfile = str(unique_path(output_dir / f"merged_{bssid_label}.22000"))
                Path(hashfile).write_text("\n".join(merged_lines) + "\n")
            try:
                cracker = JohnCracker()
            except JohnUnavailableError as exc:
                return str(exc)
            self._crack_proc_holder.clear()
            results = cracker.run_streaming(hashfile, wordlist, self._progress_fn, self._crack_proc_holder,
                                             rules=john_rules)
            if not results:
                return "no passwords recovered"
            self._queue.put(("info", "\n".join(f"{k}: {v}" for k, v in results.items())))
            return f"{len(results)} recovered"

        self._run_capture_task("Crack with John", work)


    def _crack_with_aircrack(self, paths: list[str], wordlist: str):
        from pathlib import Path
        from tkinter import simpledialog

        from ..crack.aircrack import AirCracker, AircrackUnavailableError
        from ..crack.convert import merge_captures
        from ..storage import bssids_from_paths

        bssids = bssids_from_paths(paths)
        if len(bssids) > 1:
            messagebox.showwarning(
                "ATWA-NG",
                "Select captures from one BSSID at a time. aircrack-ng needs one unambiguous target.",
            )
            return
        if bssids:
            bssid = next(iter(bssids))
        else:
            typed = simpledialog.askstring(
                "ATWA-NG",
                "Couldn't determine the BSSID from this file's path — aircrack-ng needs one "
                "to avoid its interactive network picker. Enter it directly:",
                parent=self.root,
            )
            if not typed or not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", typed.strip()):
                if typed is not None:
                    messagebox.showwarning("ATWA-NG", "Not a valid BSSID (expected aa:bb:cc:dd:ee:ff).")
                return
            bssid = typed.strip().lower()

        def work():
            if len(paths) == 1:
                capfile = paths[0]
            else:
                suffix = Path(paths[0]).suffix
                capfile = merge_captures(
                    paths,
                    output_dir=Path(paths[0]).parent,
                    output_name=f"capture_{bssid.replace(':', '-')}.merged{suffix}",
                )
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

        self._run_capture_task(f"Crack with aircrack-ng ({bssid})", work)


    def _capture_crack_john(self):
        """Quick button: force John on the current selection regardless of
        file type (caps get auto-converted), skipping _capture_crack's
        auto-detect."""
        selected = self._selected_capture_paths()
        hash_paths = [p for p in selected if p.lower().endswith(".22000")]
        cap_paths = [p for p in selected if p.lower().endswith((".cap", ".pcap", ".pcapng"))]
        if not hash_paths and not cap_paths:
            messagebox.showwarning("ATWA-NG", "Select one or more .22000 hash files or capture files first.")
            return
        from ..storage import bssids_from_paths

        bssids = bssids_from_paths(hash_paths + cap_paths)
        if len(bssids) > 1:
            messagebox.showwarning("ATWA-NG", "Select captures from one BSSID at a time.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return
        self._crack_with_john(hash_paths, wordlist, cap_paths=cap_paths)


    def _capture_crack_aircrack(self):
        """Quick button: force aircrack-ng on the current selection."""
        selected = self._selected_capture_paths()
        cap_paths = [p for p in selected if p.lower().endswith((".cap", ".pcap", ".pcapng"))]
        if not cap_paths:
            messagebox.showwarning(
                "ATWA-NG", "Aircrack-ng needs .cap/.pcap/.pcapng file(s) — select capture file(s), not .22000 hashes.")
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return
        self._crack_with_aircrack(cap_paths, wordlist)


    def _capture_cleanup(self):
        """Preview then run capture.cleanup.cleanup_handshakes — merges each
        target's captures/hashes down to one file, then all targets into
        one master, deleting originals only after each merge is written.
        Destructive, so this always previews (dry_run) before asking.
        The dry-run plan rglobs the ENTIRE capture tree — the exact walk
        that used to freeze the GUI when _refresh_captures ran it on the Tk
        thread (fix documented there), so the plan runs off-thread here
        too and only the dialog is queued back to the Tk thread."""
        from ..capture.cleanup import cleanup_handshakes

        capture_root = self.capture_dir_var.get()  # Tk-thread read

        def plan_and_confirm():
            try:
                plan = cleanup_handshakes(dry_run=True, root=capture_root)
            except OSError as exc:
                self._queue.put(("error", f"cleanup plan failed: {exc}"))
                return
            self._queue.put(("ui", lambda: self._confirm_cleanup(plan, capture_root)))

        threading.Thread(target=plan_and_confirm, daemon=True).start()


    def _confirm_cleanup(self, plan, capture_root: str) -> None:
        from ..capture.cleanup import cleanup_handshakes

        if not plan.targets:
            messagebox.showinfo("ATWA-NG", "No target folders with captures to clean up.")
            return
        total_caps = sum(len(t.cap_files) for t in plan.targets)
        total_hashes = sum(len(t.hash_files) for t in plan.targets)
        preview = (
            f"{len(plan.targets)} target folder(s), {total_caps} capture file(s) + "
            f"{total_hashes} hash file(s) total.\n\n"
            "This will consolidate files within each target only:\n"
            "  1. Merge each target's own captures into a BSSID-named file\n"
            "  2. Merge each target's own .22000 files into a BSSID-named file\n"
            "  3. Delete originals only after the replacement is written\n"
            "  4. Leave one-file targets untouched\n\n"
            "Different BSSIDs are never merged together: a multi-AP capture is not "
            "safe for aircrack-ng. This cannot be undone. Continue?"
        )
        if not messagebox.askokcancel("Cleanup Handshakes", preview):
            return

        def work():
            report = cleanup_handshakes(dry_run=False, root=capture_root)
            self._queue.put(("info", report.summary()))
            self._queue.put(("ui", self._refresh_captures))
            return f"{len(report.deleted)} file(s) deleted, {len(report.removed_dirs)} folder(s) removed"

        self._run_capture_task("Cleanup handshakes", work)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
