"""Crack dialog — what v1's HashcatDialog was supposed to be.

v1's version asked for a handshake file and a wordlist, had a Start
button, and (per the user) never actually worked end to end. This one is
wired to run for real: point it at a handshake *folder* (not a single
file) and a wordlist, hit Run, and it converts/merges whatever it finds
and cracks it — combining convert+merge+crack in one action, with a Stop
button that actually terminates the running process (John/aircrack-ng
expose their live subprocess via `run_streaming`'s proc_holder, unlike
v1 where Stop had nothing real to grab).
"""

from __future__ import annotations

import queue
import re
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..crack.aircrack import AirCracker, AircrackUnavailableError
from ..crack.convert import cap_to_22000, merge_22000_files, merge_captures
from ..crack.john import JohnCracker, JohnUnavailableError
from .theme import THEME

_CAP_SUFFIXES = {".cap", ".pcap", ".pcapng"}
_BSSID_FROM_DIRNAME_RE = re.compile(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})$")


class CrackDialog(tk.Toplevel):
    def __init__(self, parent, fonts, default_dir: str, default_wordlist: str):
        super().__init__(parent)
        self.title("Crack Handshakes")
        self.configure(bg=THEME["bg"])
        self.geometry("760x560")
        self.transient(parent)

        self._queue: queue.Queue = queue.Queue()
        self._proc_holder: dict = {}
        self._running = False

        self.dir_var = tk.StringVar(value=default_dir)
        self.wordlist_var = tk.StringVar(value=default_wordlist)
        self.backend_var = tk.StringVar(value="john")
        self.bssid_var = tk.StringVar(value=self._guess_bssid(default_dir))

        pad = {"padx": 10, "pady": 4}

        row = ttk.Frame(self)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text="Handshake folder:", width=16).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(row, text="Browse", command=self._browse_dir).pack(side=tk.LEFT)

        row = ttk.Frame(self)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text="Wordlist:", width=16).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.wordlist_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(row, text="Browse", command=self._browse_wordlist).pack(side=tk.LEFT)

        row = ttk.Frame(self)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text="Backend:", width=16).pack(side=tk.LEFT)
        ttk.Radiobutton(row, text="John (merges everything found)", variable=self.backend_var,
                         value="john", command=self._update_bssid_state).pack(side=tk.LEFT)
        ttk.Radiobutton(row, text="Aircrack-ng (one target, needs BSSID)", variable=self.backend_var,
                         value="aircrack", command=self._update_bssid_state).pack(side=tk.LEFT, padx=(10, 0))

        self.bssid_row = ttk.Frame(self)
        self.bssid_row.pack(fill=tk.X, **pad)
        ttk.Label(self.bssid_row, text="BSSID:", width=16).pack(side=tk.LEFT)
        self.bssid_entry = ttk.Entry(self.bssid_row, textvariable=self.bssid_var, width=20)
        self.bssid_entry.pack(side=tk.LEFT)
        ttk.Label(self.bssid_row, text="(auto-filled if the folder name ends in a MAC address)",
                  style="Muted.TLabel").pack(side=tk.LEFT, padx=8)

        self.output = tk.Text(self, bg=THEME["bg"], fg=THEME["fg"], insertbackground=THEME["fg"],
                               font=fonts["mono"], wrap=tk.WORD, borderwidth=0,
                               highlightthickness=1, highlightbackground=THEME["border"])
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 4))

        buttons = ttk.Frame(self)
        buttons.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.run_btn = ttk.Button(buttons, text="Run", command=self._run, style="Accent.TButton")
        self.run_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(buttons, text="Stop", command=self._stop, style="Danger.TButton", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=6)
        ttk.Button(buttons, text="Close", command=self.destroy).pack(side=tk.RIGHT)

        self._update_bssid_state()
        self.after(100, self._drain_queue)

    def _guess_bssid(self, directory: str) -> str:
        match = _BSSID_FROM_DIRNAME_RE.search(Path(directory).name)
        return match.group(1).replace("-", ":").lower() if match else ""

    def _update_bssid_state(self):
        state = tk.NORMAL if self.backend_var.get() == "aircrack" else tk.DISABLED
        self.bssid_entry.configure(state=state)

    def _browse_dir(self):
        path = filedialog.askdirectory(parent=self, title="Select handshake folder")
        if path:
            self.dir_var.set(path)
            self.bssid_var.set(self._guess_bssid(path))

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(parent=self, title="Select wordlist")
        if path:
            self.wordlist_var.set(path)

    def _append(self, text: str):
        self.output.insert(tk.END, text if text.endswith("\n") else text + "\n")
        self.output.see(tk.END)

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "line":
                    self.output.insert(tk.END, payload)
                    self.output.see(tk.END)
                elif kind == "done":
                    self._append(payload)
                    self._running = False
                    self.run_btn.configure(state=tk.NORMAL)
                    self.stop_btn.configure(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _run(self):
        if self._running:
            return
        directory = Path(self.dir_var.get())
        wordlist = self.wordlist_var.get()
        if not directory.is_dir():
            messagebox.showwarning("Crack Handshakes", "Select a valid handshake folder first.", parent=self)
            return
        if not wordlist or not Path(wordlist).is_file():
            messagebox.showwarning("Crack Handshakes", "Select a valid wordlist file first.", parent=self)
            return
        backend = self.backend_var.get()
        if backend == "aircrack" and not self.bssid_var.get().strip():
            messagebox.showwarning("Crack Handshakes", "Aircrack-ng needs a BSSID — type one or pick "
                                    "a folder whose name ends in a MAC address.", parent=self)
            return

        self._running = True
        self.run_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self._proc_holder.clear()

        if backend == "john":
            threading.Thread(target=self._run_john, args=(directory, wordlist), daemon=True).start()
        else:
            threading.Thread(target=self._run_aircrack, args=(directory, wordlist, self.bssid_var.get().strip()), daemon=True).start()

    def _on_line(self, line: str):
        self._queue.put(("line", line))

    def _run_john(self, directory: Path, wordlist: str):
        try:
            self._queue.put(("line", f"Scanning {directory} ...\n"))
            caps = sorted(p for p in directory.rglob("*") if p.suffix.lower() in _CAP_SUFFIXES)
            hashes = sorted(p for p in directory.rglob("*.22000"))
            converted = []
            for cap in caps:
                out = cap.with_suffix(cap.suffix + ".22000")
                try:
                    cap_to_22000(str(cap), str(out))
                    converted.append(out)
                    self._queue.put(("line", f"  converted {cap.name} -> {out.name}\n"))
                except Exception as exc:
                    self._queue.put(("line", f"  could not convert {cap.name}: {exc}\n"))
            all_hashes = sorted(set(hashes) | set(converted))
            if not all_hashes:
                self._queue.put(("done", "No handshake or hash material found in that folder."))
                return
            lines = merge_22000_files([str(p) for p in all_hashes])
            if not lines:
                self._queue.put(("done", "Found hash files, but they were all empty."))
                return
            batch = directory / "_atwa_crack_batch.22000"
            batch.write_text("\n".join(lines) + "\n")
            self._queue.put(("line", f"Merged {len(all_hashes)} file(s), {len(lines)} unique hash line(s) -> {batch.name}\n"))
            self._queue.put(("line", "Running john...\n"))
            try:
                cracker = JohnCracker()
            except JohnUnavailableError as exc:
                self._queue.put(("done", f"{exc}"))
                return
            results = cracker.run_streaming(str(batch), wordlist, self._on_line, self._proc_holder)
            if results:
                summary = "\n".join(f"{k}: {v}" for k, v in results.items())
                self._queue.put(("done", f"\nCRACKED:\n{summary}"))
            else:
                self._queue.put(("done", "\nNo passwords recovered."))
        except Exception as exc:
            self._queue.put(("done", f"Error: {exc}"))

    def _run_aircrack(self, directory: Path, wordlist: str, bssid: str):
        try:
            caps = sorted(p for p in directory.rglob("*") if p.suffix.lower() in _CAP_SUFFIXES)
            if not caps:
                self._queue.put(("done", "No .cap/.pcap/.pcapng files found in that folder."))
                return
            if len(caps) > 1:
                self._queue.put(("line", f"Merging {len(caps)} captures...\n"))
                capfile = merge_captures([str(p) for p in caps])
            else:
                capfile = str(caps[0])
            self._queue.put(("line", f"Running aircrack-ng against {bssid} using {Path(capfile).name}...\n"))
            try:
                cracker = AirCracker(bssid)
            except AircrackUnavailableError as exc:
                self._queue.put(("done", f"{exc}"))
                return
            results = cracker.run_streaming(capfile, wordlist, self._on_line, self._proc_holder)
            if results:
                summary = "\n".join(f"{k}: {v}" for k, v in results.items())
                self._queue.put(("done", f"\nCRACKED:\n{summary}"))
            else:
                self._queue.put(("done", "\nNo password recovered (or wrong BSSID/no full handshake in capture)."))
        except Exception as exc:
            self._queue.put(("done", f"Error: {exc}"))

    def _stop(self):
        """SIGTERM, then escalate to SIGKILL after a grace period if it
        doesn't actually exit — needed for real: a live test against
        aircrack-ng showed it can catch SIGTERM, print "Quitting
        aircrack-ng..." repeatedly, and never actually exit. terminate()
        alone is not reliable; kill() (SIGKILL) cannot be caught, so that's
        what actually guarantees the process — and the Stop button — works.
        Runs the wait/escalate off the Tk thread so the UI doesn't freeze.
        """
        proc = self._proc_holder.get("proc")
        if not proc or proc.poll() is not None:
            self._running = False
            self.run_btn.configure(state=tk.NORMAL)
            self.stop_btn.configure(state=tk.DISABLED)
            return
        self.stop_btn.configure(state=tk.DISABLED)
        self._queue.put(("line", "\n[stop requested, waiting for the process to exit...]\n"))

        def escalate():
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._queue.put(("line", "[still running after 3s, force-killing]\n"))
                proc.kill()
                proc.wait()
            self._queue.put(("done", "[stopped]"))

        threading.Thread(target=escalate, daemon=True).start()
