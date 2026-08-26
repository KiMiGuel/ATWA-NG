"""Capture WPA 4-way handshake EAPOL frames until a crackable pair is seen.

Gating mirrors v1's MESSAGEPAIR-byte-&-0x07 classification (main.py
classify_22000_text): a pair with only M1+M2 is CHALLENGE — unverified,
since the AP never confirmed the client's MIC — while M2+M3 is AUTHORIZED,
since the AP itself validated the proof before replying with M3. The
v1.6.0 fix this preserves: CHALLENGE-only must NOT stop auto-deauth loops.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

from ..frames import eapol_key_info
from ..radio import set_channel


class HandshakeStatus(Enum):
    """Capture quality for one (AP, client) pair."""

    NONE = "none"
    CHALLENGE = "challenge"
    AUTHORIZED = "authorized"


@dataclass
class HandshakeCapture:
    """Tracks EAPOL messages 1-3 seen per (AP, client) pair."""

    messages: dict[tuple[str, str], set[int]] = field(default_factory=dict)

    def add(self, ap: str, client: str, msg_no: int) -> None:
        """Record a handshake message number for a pair."""
        self.messages.setdefault((ap, client), set()).add(msg_no)

    def status(self, ap: str, client: str) -> HandshakeStatus:
        """Classify a pair's capture quality (v1 MESSAGEPAIR & 0x07 equivalent)."""
        seen = self.messages.get((ap, client), set())
        if {2, 3} <= seen:
            return HandshakeStatus.AUTHORIZED
        if {1, 2} <= seen:
            return HandshakeStatus.CHALLENGE
        return HandshakeStatus.NONE

    def complete(self, ap: str, client: str) -> bool:
        """True once any crackable material (CHALLENGE or AUTHORIZED) is held."""
        return self.status(ap, client) is not HandshakeStatus.NONE

    def authorized(self, ap: str, client: str) -> bool:
        """True only once the AP itself confirmed proof (M3 seen).

        This is the sole signal that should stop an attack loop's deauth
        rounds. CHALLENGE (M1+M2 only) is unverified and must keep the loop
        running — regressing this was the v1.6.0 bug.
        """
        return self.status(ap, client) is HandshakeStatus.AUTHORIZED


def _classify(pkt) -> int | None:
    """Return handshake message number (1-3 relevant) or None."""
    info = eapol_key_info(pkt)
    if info is None:
        return None
    mic_set, ack_set = info
    if ack_set and not mic_set:
        return 1
    if not ack_set and mic_set:
        return 2
    if ack_set and mic_set:
        return 3
    return None


def capture_handshake(
    iface: str,
    bssid: str,
    channel: int | None = None,
    timeout: float = 60.0,
    outfile: str | None = None,
    stop_event=None,
) -> HandshakeCapture:
    """Sniff EAPOL frames for bssid until a complete pair, timeout, or
    stop_event fires.

    Uses AsyncSniffer rather than blocking sniff() so an external
    stop_event can actually abort the capture. Without this, a caller
    that wants to cancel mid-capture (e.g. OmniOrchestrator.stop()) has
    no way to reclaim the interface — the sniffer keeps running for the
    rest of `timeout` in the background even after the caller has moved
    on, holding the raw socket open the whole time.
    """
    if channel is not None:
        set_channel(iface, channel)
    cap = HandshakeCapture()
    writer = PcapWriter(outfile, append=True, sync=True) if outfile else None

    def handler(pkt) -> None:
        if not pkt.addr3 or pkt.addr3.lower() != bssid.lower():
            return
        msg_no = _classify(pkt)
        if msg_no is None:
            return
        ap, client = pkt.addr3, pkt.addr1 if msg_no % 2 == 1 else pkt.addr2
        cap.add(ap, client, msg_no)
        if writer:
            writer.write(pkt)

    def stop_filter(pkt) -> bool:
        # Only an AUTHORIZED pair (AP confirmed via M3) ends the sniff early;
        # CHALLENGE-only (M1+M2) keeps listening in case M3 still arrives.
        return any(cap.authorized(ap, cl) for ap, cl in cap.messages)

    sniffer = AsyncSniffer(iface=iface, prn=handler, stop_filter=stop_filter, store=False)
    sniffer.start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            break
        if not sniffer.thread or not sniffer.thread.is_alive():
            break  # stop_filter already ended the sniff (AUTHORIZED capture)
        time.sleep(0.2)
    try:
        sniffer.stop()
    except Exception:
        pass
    if writer:
        writer.close()
    return cap
