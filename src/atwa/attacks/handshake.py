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

from ..eapol.utils import message_number
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
    # Monotonic memo: `messages` sets only ever gain members, so a pair's
    # status can only climb -- AUTHORIZED, once reached, can never regress.
    # stop_filter evaluates this on every sniffed frame (thousands/sec on a
    # busy band), so the flag keeps it O(1) instead of re-classifying every
    # pair per packet. Maintained solely by add(); nothing else mutates
    # `messages` (enforced by that being the only write site).
    authorized_found: bool = field(default=False, init=False, repr=False)

    def add(self, ap: str, client: str, msg_no: int) -> None:
        """Record a handshake message number for a pair."""
        self.messages.setdefault((ap, client), set()).add(msg_no)
        if not self.authorized_found and self.status(ap, client) is HandshakeStatus.AUTHORIZED:
            self.authorized_found = True

    def status(self, ap: str, client: str) -> HandshakeStatus:
        """Classify a pair's capture quality."""
        seen = self.messages.get((ap, client), set())
        if {2, 3} <= seen:
            return HandshakeStatus.AUTHORIZED
        if {1, 2} <= seen:
            return HandshakeStatus.CHALLENGE
        return HandshakeStatus.NONE

    def authorized(self, ap: str, client: str) -> bool:
        """True only once the AP itself confirmed proof (M3 seen).

        Used by this module's own stop_filter (passive listening only —
        see the module docstring). Attack loops deciding whether to keep
        deauthing should use attacks/logic.py's meets_threshold() instead.
        """
        return self.status(ap, client) is HandshakeStatus.AUTHORIZED


def _classify(pkt) -> int | None:
    """Handshake message number 1-4, or None if this is not one.

    Delegates to eapol.utils.message_number, which applies the
    IEEE 802.11-2024 12.7.2 rules: Key Information bits decide M1/M2/M3/M4
    for RSN, legacy WPA frames fall back to the replay counter, group
    (GTK) frames and Request/Error frames are ignored. The group-key
    exclusion matters because the group M1 carries the same ACK/MIC
    profile as pairwise M3, which would otherwise escalate a CHALLENGE
    pair to AUTHORIZED and stop the sniff on a capture hcxpcapngtool then
    finds empty.
    """
    eapol = pkt.getlayer(EAPOL)
    if eapol is None:
        return None
    return message_number(bytes(eapol))


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
    # The "discard when nothing was captured" logic below may only delete a
    # file THIS call created: the writer opens append=True, so outfile can
    # already hold a good capture from a previous run (OMNI reuses
    # <bssid>.pcap across re-runs). Deleting that because the current round
    # saw no reconnect would destroy real captured material.
    outfile_existed = outfile is not None and Path(outfile).exists()
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
        # when cap.messages is completely empty. Never touch a file that
        # existed before this call — that guard is what keeps a re-run with
        # no reconnect from deleting the previous run's capture.
        if outfile and not outfile_existed:
            try:
                Path(outfile).unlink()
                log(f"discarded empty capture file ({outfile})")
            except OSError:
                pass
    return cap
