"""Scapy helpers to craft and parse 802.11 beacon/probe/deauth/EAPOL frames."""

from __future__ import annotations

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

BROADCAST = "ff:ff:ff:ff:ff:ff"


def craft_rsn_ie(akms: list[int] | None = None, mfpc: bool = False, mfpr: bool = False) -> Dot11Elt:
    """Craft a minimal RSN IE (CCMP group/pairwise, given AKM suite types)."""
    akms = akms if akms is not None else [2]  # default: PSK
    caps = (0x40 if mfpc else 0) | (0x80 if mfpr else 0)
    info = (
        b"\x01\x00"  # version 1
        + b"\x00\x0f\xac\x04"  # group cipher: CCMP
        + b"\x01\x00\x00\x0f\xac\x04"  # 1 pairwise: CCMP
        + len(akms).to_bytes(2, "little")
        + b"".join(b"\x00\x0f\xac" + bytes([a]) for a in akms)
        + caps.to_bytes(2, "little")
    )
    return Dot11Elt(ID=48, info=info)


def craft_beacon(
    bssid: str,
    ssid: str,
    channel: int = 1,
    privacy: bool = False,
    extra_ies: list[Dot11Elt] | None = None,
) -> Packet:
    """Craft a beacon frame advertising ssid from bssid on channel."""
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="privacy" if privacy else 0)
    essid = Dot11Elt(ID="SSID", info=ssid.encode())
    ds = Dot11Elt(ID="DSset", info=bytes([channel]))
    pkt = RadioTap() / dot11 / beacon / essid / ds
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def craft_probe_resp(
    bssid: str,
    ssid: str,
    client: str,
    channel: int = 1,
    privacy: bool = False,
    extra_ies: list[Dot11Elt] | None = None,
) -> Packet:
    """Craft a probe response from bssid to client."""
    dot11 = Dot11(type=0, subtype=5, addr1=client, addr2=bssid, addr3=bssid)
    pkt = (
        RadioTap()
        / dot11
        / Dot11ProbeResp(cap="privacy" if privacy else 0)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def craft_deauth(bssid: str, client: str = BROADCAST, reason: int = 7) -> Packet:
    """Craft a deauthentication frame from bssid to client (default broadcast)."""
    dot11 = Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
    return RadioTap() / dot11 / Dot11Deauth(reason=reason)


def _inject_radiotap() -> RadioTap:
    """RadioTap header for frames we actually inject over the air (not the
    synthetic beacon/probe-resp used only to build test fixtures).

    ORDER (only) asks the kernel not to reorder this frame relative to
    other injected frames — safe with no cost. NOSEQ was dropped: it
    tells the kernel to leave the sequence-control field alone, which is
    only a win if *we* then manage SC ourselves — we don't, so every
    frame was going out as SC=0 every time, a textbook duplicate-frame
    signature real receivers are required to silently drop. Confirmed via
    aircrack-ng's own aireplay-ng.c (do_attack_fake_auth), which does
    manage SC explicitly per send. Sourced from Mathy Vanhoef's
    wifi-injection research (WiSec 2023), github.com/vanhoefm/wifi-injection.
    """
    return RadioTap(present="TXFlags", TXFlags="ORDER")


def craft_auth(bssid: str, client: str, seq: int = 1) -> Packet:
    """Craft an open-system authentication request (used for PMKID attacks)."""
    dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)
    return _inject_radiotap() / dot11 / Dot11Auth(algo=0, seqnum=seq, status=0)


def craft_assoc_req(bssid: str, client: str, ssid: str, extra_ies: list[Dot11Elt] | None = None) -> Packet:
    """Craft an association request from client to bssid (needed for WPS).

    cap includes "privacy" — every WPA2 AP's own beacon has that bit set,
    and aircrack-ng's fake-auth echoes the AP's real captured capability
    info rather than a bare ESS-only value; this is the same idea without
    needing a live beacon lookup. Extended Supported Rates IE added
    alongside the basic 8-rate set for the same "look like a real station"
    reason (aircrack-ng's own RATES table is fuller than 8 bytes too).
    """
    dot11 = Dot11(type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid)
    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ext_rates = Dot11Elt(ID=50, info=b"\x30\x48\x60\x6c")  # Extended Supported Rates
    pkt = (
        _inject_radiotap()
        / dot11
        / Dot11AssoReq(cap="ESS+privacy", listen_interval=3)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / rates
        / ext_rates
    )
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def assoc_resp_status(pkt: Packet) -> int | None:
    """Return the association-response status code (0 = success), or None."""
    resp = pkt.getlayer(Dot11AssoResp)
    return resp.status if resp else None


def _walk_elts(pkt: Packet):
    """Yield every Dot11Elt information element in the frame."""
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None


def ssid_of(pkt: Packet) -> str | None:
    """Return the SSID element value, or None for hidden/missing SSIDs.

    Real SSIDs aren't guaranteed UTF-8 (older/cheap firmware, non-UTF8
    locales) — try UTF-8 first, fall back to latin-1 (never fails, every
    byte 0-255 is a valid codepoint) instead of always landing on U+FFFD
    replacement chars, which render as tofu boxes in the GUI regardless
    of what the original bytes actually were.
    """
    for elt in _walk_elts(pkt):
        if elt.ID == 0:
            try:
                return elt.info.decode("utf-8") or None
            except UnicodeDecodeError:
                return elt.info.decode("latin-1") or None
    return None


def channel_of(pkt: Packet) -> int | None:
    """Return the DS parameter set channel, or None."""
    for elt in _walk_elts(pkt):
        if elt.ID == 3 and elt.info:
            return elt.info[0]
    return None


def bssid_of(pkt: Packet) -> str | None:
    """Return the BSSID (addr3) of an 802.11 frame, or None."""
    dot11 = pkt.getlayer(Dot11)
    return dot11.addr3 if dot11 else None


def is_eapol(pkt: Packet) -> bool:
    """True if the frame carries an EAPOL (802.1X) payload."""
    return pkt.haslayer(EAPOL)


def eapol_key_info(pkt: Packet) -> tuple[bool, bool] | None:
    """Return (mic_set, ack_set) from a WPA key EAPOL frame, else None.

    The two flag bits identify handshake messages: M1 has ack+!mic,
    M2 has mic+!ack, M3 has ack+mic (with install), M4 has mic+!ack.
    """
    if not is_eapol(pkt):
        return None
    eapol = pkt.getlayer(EAPOL)
    raw = bytes(eapol.payload)
    if len(raw) < 6:
        return None
    # WPA key frame: [descriptor_type(1)][key_info(2, big-endian)]...
    key_info = int.from_bytes(raw[1:3], "big")
    mic_set = bool(key_info & 0x0100)
    ack_set = bool(key_info & 0x0080)
    return mic_set, ack_set
