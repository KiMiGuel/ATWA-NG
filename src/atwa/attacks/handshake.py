"""Capture WPA 4-way handshake EAPOL frames until a crackable pair is seen.

Classification: a pair with only M1+M2 is CHALLENGE — unverified, since
the AP never confirmed the client's MIC — while M2+M3 is AUTHORIZED,
since the AP itself validated the proof before replying with M3.
CHALLENGE-only must NOT stop auto-deauth loops, only AUTHORIZED should.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from scapy.data import DLT_IEEE802_11_RADIO
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

from ..frames import eapol_key_info
from ..radio import ensure_channel


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
        """Classify a pair's capture quality."""
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
        rounds. CHALLENGE (M1+M2 only) is unverified and must keep the
        loop running.
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
    progress_fn=None,
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
    log = progress_fn or (lambda msg: None)
    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")
    log(f"listening for EAPOL on {bssid} (up to {timeout:.0f}s)...")
    cap = HandshakeCapture()
    # linktype forced explicitly: without it, PcapWriter guesses from the
    # first packet's own .linktype attribute and warns + silently falls
    # back to Ethernet ("unknown LL type for NoneType. Using type 1
    # (Ethernet)") whenever that's absent — not just a noisy warning, the
    # capture file's header would then claim Ethernet framing while
    # actually containing raw 802.11/RadioTap frames, which is wrong data
    # for any downstream tool (aircrack-ng, hcxpcapngtool, Wireshark) to
    # parse. Monitor-mode sniffs always come back RadioTap-wrapped, so the
    # correct type is DLT_IEEE802_11_RADIO, always, not a guess.
    writer = PcapWriter(outfile, linktype=DLT_IEEE802_11_RADIO, append=True, sync=True) if outfile else None
    beacon_written = False

    def handler(pkt) -> None:
        nonlocal beacon_written
        if not pkt.addr3 or pkt.addr3.lower() != bssid.lower():
            return
        # hcxpcapngtool refuses to convert an EAPOL-only capture -- it needs
        # a beacon or probe-response frame too, since that's the only place
        # the ESSID (mandatory for PMK computation) lives. Grab exactly one,
        # the first seen, alongside the EAPOL frames -- beacons arrive every
        # ~100ms so this is essentially free during any real listen window.
        if writer and not beacon_written and (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            writer.write(pkt)
            beacon_written = True
            log("beacon frame captured (carries the ESSID needed for hash conversion)")
        msg_no = _classify(pkt)
        if msg_no is None:
            return
        ap, client = pkt.addr3, pkt.addr1 if msg_no % 2 == 1 else pkt.addr2
        is_new = msg_no not in cap.messages.get((ap, client), set())
        cap.add(ap, client, msg_no)
        if is_new:
            log(f"EAPOL M{msg_no} seen (client {client}) -> {cap.status(ap, client).value}")
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
    except Exception:  # noqa: BLE001, S110 - stop can race with thread teardown
        pass
    if writer:
        writer.close()
    if not cap.messages:
        log("no EAPOL frames seen for this BSSID")
        # Trash: a deauth round that got no reconnect at all (or just a lone
        # beacon frame with zero handshake material) is worthless downstream
        # -- nothing to crack, ever. Discard it here rather than letting the
        # capture folder fill up with empty files from every failed round.
        # CHALLENGE-only captures (M1+M2, no M3) are NOT trash -- they're
        # still real, potentially crackable material -- so this only fires
        # when cap.messages is completely empty.
        if outfile:
            try:
                Path(outfile).unlink()
                log(f"discarded empty capture file ({outfile})")
            except OSError:
                pass
    return cap
