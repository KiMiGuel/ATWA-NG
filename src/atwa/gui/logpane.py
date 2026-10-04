"""Log pane, status bar, and the queue that marshals worker threads
back onto the Tk main loop.
"""

from __future__ import annotations

import functools
import queue
import tkinter as tk
from tkinter import messagebox, ttk

from .. import __version__
from .state import GuiState


class LogPaneMixin(GuiState):

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
        for b in self.capture_buttons:
            b.configure(state=state)
        self.pincer_button.configure(state=tk.DISABLED if (busy or not self.alfa_pair) else tk.NORMAL)


    def _queue_scan_update(self):
        """Coalesce scan refreshes when the Tk thread falls behind."""
        with self._queue_coalesce_lock:
            if self._scan_update_queued:
                return
            self._scan_update_queued = True
        self._queue.put(("scan_update", None))


    def _queue_signal_sample(self, value: int | None):
        """Keep only the newest signal sample while the GUI is busy."""
        with self._queue_coalesce_lock:
            self._pending_signal_sample = value
            if self._signal_sample_queued:
                return
            self._signal_sample_queued = True
        self._queue.put(("signal_sample", None))


    def _drain_queue(self):
        # Reschedule in `finally`, not as the last line of a plain `try`:
        # an exception raised while handling any one item (e.g. a race
        # between this loop and a background thread mutating shared state)
        # used to escape past the `except queue.Empty` below and skip the
        # reschedule entirely, permanently killing all future log/status/
        # busy updates for the rest of the process — confirmed live
        # (2026-08-28), `_render_targets()` hit "dictionary changed size
        # during iteration" once and every attack after that ran for real
        # but never showed anything again until the GUI was restarted.
        # Each item is now also handled in its own try/except so one bad
        # item can't block the rest of the same batch either.
        try:
            while True:
                try:
                    kind, payload = self._queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    if kind == "log":
                        self._append_log(payload)
                    elif kind == "status":
                        self.status_var.set(payload)
                    elif kind == "scan_update":
                        with self._queue_coalesce_lock:
                            self._scan_update_queued = False
                        self._render_targets()
                    elif kind == "signal_sample":
                        with self._queue_coalesce_lock:
                            sample = self._pending_signal_sample
                            self._pending_signal_sample = None
                            self._signal_sample_queued = False
                        self.signal_graph.add_sample(sample)
                    elif kind == "auto_deauth_done":
                        self.auto_deauth_var.set(False)
                    elif kind == "update_available":
                        self._show_update_available(payload)
                    elif kind == "capture_size":
                        self.capture_size_var.set(self._format_capture_size(payload))
                    elif kind == "busy":
                        self._set_busy(payload)
                    elif kind == "error":
                        messagebox.showerror("ATWA-NG", payload)
                    elif kind == "info":
                        messagebox.showinfo("ATWA-NG", payload)
                    elif kind == "captures_ready":
                        self._populate_capture_tree(payload)
                    elif kind == "task_result":
                        result_kind, result = payload
                        if result_kind == "inspect_all_done":
                            self._on_inspect_all_done(result)
                    elif kind == "ui":
                        payload()  # generic "run this callable on the Tk thread" escape hatch
                except Exception as exc:  # noqa: BLE001 - one bad queue item must not kill the drain loop
                    self._append_log(f"    (internal) error handling {kind!r} update: {exc}")
        finally:
            self.root.after(100, self._drain_queue)


    def _show_update_available(self, result):
        from ..update import apply_update

        message = f"ATWA-NG {result.latest} is available (installed: {result.current})."
        if result.release_url:
            message += f"\n\n{result.release_url}"
        if messagebox.askyesno("ATWA-NG update available", message + "\n\nInstall now?"):
            self._queue.put(("log", "Applying update..."))
            success, msg = apply_update()
            if success:
                self._queue.put(("info", f"Update successful: {msg}\nRestart ATWA-NG to use the new version."))
            else:
                self._queue.put(("error", f"Update failed: {msg}"))


    # ------------------------------------------------------------------
    # Background execution: run fn() off the UI thread, results/log lines
    # come back through a queue drained on the Tk main loop via `after`.
    # ------------------------------------------------------------------
    def _check_for_updates(self):
        from ..update import check_for_update

        result = check_for_update(__version__, timeout=3.0)
        if result.error:
            self._queue.put(("log", f"update check unavailable: {result.error}"))
        elif result.update_available:
            self._queue.put(("update_available", result))


    def _format_capture_size(self, size: int | None) -> str:
        if size is None:
            return ""
        if size < 1024:
            return f"Capture: {size} B"
        if size < 1024 ** 2:
            return f"Capture: {size / 1024:.1f} KB"
        return f"Capture: {size / 1024 ** 2:.1f} MB"


    def _show_scroll_dialog(self, title: str, text: str, *, buttons: tuple[str, ...] = ("OK",)) -> str | None:
        """Fixed-size, word-wrapped, scrollable dialog -- messagebox.showinfo
        grows unbounded-tall with one line per file, unreadable past a
        handful of results (2026-08-28 user report)."""
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.configure(bg=self.THEME["bg"])
        dlg.geometry("560x480")
        dlg.transient(self.root)
        dlg.grab_set()

        result: dict[str, str | None] = {"choice": None}

        def choose(label: str | None) -> None:
            result["choice"] = label
            dlg.destroy()

        # btn_row packed (and its space reserved) BEFORE text_frame, and
        # anchored side=BOTTOM -- text_frame's fill=BOTH/expand=True below
        # would otherwise claim all the fixed 560x480 window's space first
        # and push the buttons off the bottom edge, invisible, on displays/
        # themes where the text content renders taller than expected. Same
        # bug, same fix as crack_dialog.py's Run/Stop/Close row (2026-08-28).
        btn_row = ttk.Frame(dlg)
        btn_row.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=(0, 8))
        for label in buttons:
            style = "Accent.TButton" if label in ("OK", "Yes") else "TButton"
            ttk.Button(btn_row, text=label, command=functools.partial(choose, label), style=style).pack(
                side=tk.RIGHT, padx=4)

        text_frame = ttk.Frame(dlg)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt = tk.Text(text_frame, wrap=tk.WORD, bg=self.THEME["panel_alt"], fg=self.THEME["bright"],
                       insertbackground=self.THEME["bright"], relief="solid", borderwidth=1,
                       highlightthickness=0, font=self.fonts["mono"])
        scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt.insert("1.0", text)
        txt.configure(state=tk.DISABLED)
        dlg.protocol("WM_DELETE_WINDOW", lambda: choose(None))
        dlg.wait_visibility()
        dlg.focus_set()
        self.root.wait_window(dlg)
        return result["choice"]
