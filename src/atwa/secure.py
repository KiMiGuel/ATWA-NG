"""Security-profile parsing (RSN/WPA IEs, PMF) and attack recommendation,
sourced directly from beacon/probe-response IEs rather than parsed scan
output.
"""

from __future__ import annotations

from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.packet import Packet

from .frames import _walk_elts
from .wps.tlv import (
    ATTR_AP_SETUP_LOCKED,
    ATTR_DEVICE_NAME,
    ATTR_MANUFACTURER,
    ATTR_MODEL_NAME,
    ATTR_MODEL_NUMBER,
    WPS_VENDOR_OUI_TYPE,
    decode_tlvs,
)

WPA_VENDOR_OUI = b"\x00\x50\xf2\x01"  # Microsoft OUI + WPA type 1
WPS_VENDOR_OUI = WPS_VENDOR_OUI_TYPE

# RSN AKM suite types (last byte of 00:0F:AC:<type>)
AKM_PSK = 2
AKM_SAE = 8

RSN_CAP_MFPC = 0x40  # management frame protection capable
RSN_CAP_MFPR = 0x80  # management frame protection required


def _rsn_info(elt_info: bytes) -> tuple[set[int], int] | None:
    """Parse an RSN IE body → (akm_types, rsn_capabilities), or None."""
    try:
        pos = 2  # version
        pos += 4  # group cipher
        pairwise_count = int.from_bytes(elt_info[pos : pos + 2], "little")
        pos += 2 + 4 * pairwise_count
        akm_count = int.from_bytes(elt_info[pos : pos + 2], "little")
        pos += 2
        akms = {elt_info[pos + 4 * i + 3] for i in range(akm_count)}
        pos += 4 * akm_count
        caps = int.from_bytes(elt_info[pos : pos + 2], "little") if pos + 2 <= len(elt_info) else 0
        return akms, caps
    except (IndexError, ValueError):
        return None


def security_profile(pkt: Packet) -> dict:
    """Derive {security, pmf} from a beacon/probe-response frame.

    security: open | WEP | WPA | WPA2 | WPA3 | transition
    pmf: none | capable | required | unknown (unknown = WPA2 without caps,
    deauth still worth attempting).
    """
    cap_layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
    privacy = bool(cap_layer and "privacy" in (cap_layer.cap or []))

    rsn = None
    for elt in _walk_elts(pkt):
        if elt.ID == 48:
            rsn = _rsn_info(bytes(elt.info))
    # WPA1 vendor IE (ID 221, OUI 00:50:f2:01): scapy may swallow it into a
    # Raw payload, so detect it in the raw frame bytes instead.
    raw = bytes(pkt)
    wpa_vendor = False
    idx = raw.find(WPA_VENDOR_OUI)
    while idx != -1:
        if idx >= 2 and raw[idx - 2] == 221:
            wpa_vendor = True
            break
        idx = raw.find(WPA_VENDOR_OUI, idx + 1)

    if not privacy and rsn is None and not wpa_vendor:
        return {"security": "open", "pmf": "none"}
    if rsn is None:
        if wpa_vendor:
            return {"security": "WPA", "pmf": "unknown"}
        return {"security": "WEP", "pmf": "none"}

    akms, caps = rsn
    sae = AKM_SAE in akms
    psk = AKM_PSK in akms
    if sae and psk:
        security = "transition"
    elif sae:
        security = "WPA3"
    else:
        security = "WPA2"

    if caps & RSN_CAP_MFPR:
        pmf = "required"
    elif caps & RSN_CAP_MFPC:
        pmf = "capable"
    else:
        pmf = "unknown" if security == "WPA2" else "none"
    return {"security": security, "pmf": pmf}


def wps_profile(pkt: Packet) -> dict | None:
    """Extract WPS IE data from a beacon/probe-response.

    Returns None if the frame carries no WPS vendor IE (OUI 00:50:F2,
    type 04). Otherwise returns a dict:

        {
            "state": "enabled" | "locked",
            "manufacturer": str | None,
            "model_name": str | None,
            "model_number": str | None,
            "device_name": str | None,
        }

    This closes the reconnaissance gap vs. `wash`: in addition to the AP
    Setup Locked flag, we now surface manufacturer/model/device-name TLVs
    when the AP advertises them.

    Same raw-byte-search approach as the WPA1 vendor IE check above:
    scapy can swallow vendor-specific IEs into a Raw payload instead of
    exposing them as walkable elements, so search the frame bytes for the
    OUI+type signature directly rather than relying on _walk_elts. The IE's
    own length byte (idx-1) bounds the WSC-TLV blob before handing it to
    the same decode_tlvs() the M1..M7 exchange uses (WFA vendor IE 221 and
    a beacon's WPS IE share the same [type(2) len(2) value] attribute
    format)."""
    raw = bytes(pkt)
    idx = raw.find(WPS_VENDOR_OUI)
    while idx != -1:
        if idx >= 2 and raw[idx - 2] == 221:
            elt_len = raw[idx - 1]
            tlv_end = idx + elt_len
            if tlv_end <= len(raw):
                attrs = decode_tlvs(raw[idx + 4 : tlv_end])
                locked = attrs.get(ATTR_AP_SETUP_LOCKED, b"\x00") != b"\x00"
                return {
                    "state": "locked" if locked else "enabled",
                    "manufacturer": _decode_str(attrs.get(ATTR_MANUFACTURER)),
                    "model_name": _decode_str(attrs.get(ATTR_MODEL_NAME)),
                    "model_number": _decode_str(attrs.get(ATTR_MODEL_NUMBER)),
                    "device_name": _decode_str(attrs.get(ATTR_DEVICE_NAME)),
                }
        idx = raw.find(WPS_VENDOR_OUI, idx + 1)
    return None


def _decode_str(value: bytes | None) -> str | None:
    """Decode a WSC UTF-8 attribute value, returning None if missing/empty."""
    if not value:
        return None
    try:
        return value.decode("utf-8").strip() or None
    except UnicodeDecodeError:
        return None


def recommend_attack(ap) -> dict:
    """Pick the primary attack for an AP profile → {"attack", "reason"}.

    Routing: PMKID when PMF blocks deauth, downgrade twin for
    transition mode, deauth+handshake otherwise.
    """
    security = getattr(ap, "security", None)
    pmf = getattr(ap, "pmf", None)
    if security == "open":
        return {"attack": "none", "reason": "Open network — no handshake to capture (consider evil-twin/portal audit)."}
    if security == "WEP":
        return {"attack": "wep_replay", "reason": "WEP: ARP-request replay to force IVs, then PTW crack."}
    if pmf == "required":
        return {"attack": "pmkid", "reason": "PMF required (802.11w): deauth blocked — clientless PMKID still works; else online SAE guessing."}
    if security == "transition":
        return {"attack": "downgrade_twin", "reason": "WPA3 transition mode: rogue WPA2-only twin forces fallback to crackable WPA2 handshake (PMKID also viable)."}
    return {"attack": "deauth_handshake", "reason": "Deauth connected clients to force a 4-way handshake capture; PMKID is a quiet clientless alternative."}
