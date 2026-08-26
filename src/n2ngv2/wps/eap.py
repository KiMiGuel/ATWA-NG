"""EAPOL/EAP framing for the WPS (EAP-WSC) exchange, over 802.11 data frames.

Built as raw bytes (like this project's existing EAPOL-key handling in
frames.py) rather than via scapy's generic EAP layer, since EAP-Expanded
(type 254, vendor WFA/SimpleConfig) needs precise control over the vendor
triple and WSC opcode/flags that scapy doesn't model.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet, Raw

from .tlv import EAP_TYPE_EXPANDED, WFA_VENDOR_ID, WSC_VENDOR_TYPE

EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_START = 1

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2

EAP_TYPE_IDENTITY = 1

WSC_OP_START = 0x01
WSC_OP_ACK = 0x02
WSC_OP_NACK = 0x03
WSC_OP_MSG = 0x04
WSC_OP_DONE = 0x05
WSC_OP_FRAG_ACK = 0x06

# WSC vendor-data flags byte (the byte right after the opcode).
WSC_FLAG_MF = 0x01  # More Fragments follow
WSC_FLAG_LF = 0x02  # 2-byte total-length field present (first fragment only)

# Conservative: comfortably under any real 802.11 frame body, and under
# every message this project actually sends today (M2's ~400-byte TLV
# body, the largest, still fits in one fragment) — this exists for
# protocol completeness against AP registrar payloads or future messages
# that don't, not because anything here currently needs it.
DEFAULT_WSC_FRAGMENT_MTU = 1000


def _wrap_eapol(iface_bssid: str, client: str, eapol_bytes: bytes) -> Packet:
    """Wrap raw EAPOL bytes in the 802.11 Data/LLC/SNAP stack (station -> AP).

    RadioTap TXFlags=ORDER for the same reason as frames.py's
    _inject_radiotap() — see that docstring (NOSEQ dropped: we don't
    manage sequence control ourselves, so it was just freezing SC=0).
    """
    dot11 = Dot11(type=2, subtype=0, FCfield="to_DS", addr1=iface_bssid, addr2=client, addr3=iface_bssid)
    return (
        RadioTap(present="TXFlags", TXFlags="ORDER")
        / dot11
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / Raw(load=eapol_bytes)
    )


def craft_eapol_start(bssid: str, client: str, version: int = 1) -> Packet:
    """EAPOL-Start: version(1), type=1, len=0, no payload.

    `version` is the 802.1X protocol version byte (1=2001, 2=2004, 3=2010).
    Some AP firmware silently drops EAPOL frames whose version byte doesn't
    match what it enforces — not spec-mandated, but observed in the wild.
    Defaults to 1 (this project's original, unconditional value) so callers
    that don't care keep the old behavior.
    """
    eapol_bytes = bytes([version, EAPOL_TYPE_START]) + (0).to_bytes(2, "big")
    return _wrap_eapol(bssid, client, eapol_bytes)


def _eap_packet(code: int, identifier: int, eap_type: int | None, type_data: bytes) -> bytes:
    body = bytes([eap_type]) + type_data if eap_type is not None else type_data
    length = 4 + len(body)
    return bytes([code, identifier]) + length.to_bytes(2, "big") + body


def _eapol_wrap_eap(eap_bytes: bytes, version: int = 1) -> bytes:
    return bytes([version, EAPOL_TYPE_EAP_PACKET]) + len(eap_bytes).to_bytes(2, "big") + eap_bytes


def craft_eap_identity_response(
    bssid: str, client: str, identifier: int, identity: bytes, version: int = 1,
) -> Packet:
    """EAP-Response/Identity, presenting the WSC registrar identity string.

    `version` should match whichever EAPOL-Start version the AP actually
    answered — mixing versions mid-session is untested territory, keep the
    whole exchange on one version once EAPOL-Start gets a reply.
    """
    eap = _eap_packet(EAP_CODE_RESPONSE, identifier, EAP_TYPE_IDENTITY, identity)
    return _wrap_eapol(bssid, client, _eapol_wrap_eap(eap, version))


EAP_CODE_FAILURE = 4


def craft_eap_failure(bssid: str, client: str, identifier: int, version: int = 1) -> Packet:
    """EAP-Failure: explicitly closes out a WPS session.

    Reference tool reaver sends this at the end of every session
    (its -E/--eap-terminate behavior) to cleanly signal termination
    rather than just going silent — abandoning a session without this
    is a plausible reason an AP's WPS state machine gets stuck waiting
    on us instead of resetting for the next attempt.
    """
    eap = _eap_packet(EAP_CODE_FAILURE, identifier, None, b"")
    return _wrap_eapol(bssid, client, _eapol_wrap_eap(eap, version))


def craft_wsc_msg(
    bssid: str, client: str, identifier: int, opcode: int, tlv_data: bytes, version: int = 1,
) -> Packet:
    """EAP-Response/Expanded(WSC) carrying one WSC opcode + TLV blob,
    unfragmented (flags=0x00, no length field).

    Every message this project builds today (M2/M4/M6) fits comfortably
    under DEFAULT_WSC_FRAGMENT_MTU in one frame, so this single-fragment
    form is still what every existing call site wants. For a payload that
    might not fit, use fragment_wsc_vendor_payload() + craft_wsc_msg_fragment()
    to build and send each piece, waiting for a WSC_FRAG_ACK between
    non-final fragments (see attacks/wps.py's send helper).
    """
    vendor_data = bytes([opcode, 0x00]) + tlv_data
    type_data = WFA_VENDOR_ID + WSC_VENDOR_TYPE + vendor_data
    eap = _eap_packet(EAP_CODE_RESPONSE, identifier, EAP_TYPE_EXPANDED, type_data)
    return _wrap_eapol(bssid, client, _eapol_wrap_eap(eap, version))


def fragment_wsc_vendor_payload(payload: bytes, mtu: int = DEFAULT_WSC_FRAGMENT_MTU) -> list[bytes]:
    """Split a WSC opcode's TLV payload into [flags(1)[+len(2)]+chunk]
    pieces per the WSC fragmentation format:

      unfragmented : flags=0x00                          + full payload
      first         : flags=LF|MF, 2-byte BE total length + chunk
      middle        : flags=MF                            + chunk
      final         : flags=0x00                          + chunk

    Each returned element already has its flags(+length) header attached;
    craft_wsc_msg_fragment() just adds the opcode and the EAP/EAPOL wrap.
    Single-element list (flags=0x00) when payload already fits in mtu.
    """
    if len(payload) <= mtu:
        return [b"\x00" + payload]

    fragments = []
    offset = 0
    fragments.append(struct.pack(">BH", WSC_FLAG_LF | WSC_FLAG_MF, len(payload)) + payload[offset:offset + mtu])
    offset += mtu
    while len(payload) - offset > mtu:
        fragments.append(struct.pack(">B", WSC_FLAG_MF) + payload[offset:offset + mtu])
        offset += mtu
    fragments.append(b"\x00" + payload[offset:])
    return fragments


def craft_wsc_msg_fragment(
    bssid: str, client: str, identifier: int, opcode: int, vendor_fragment: bytes, version: int = 1,
) -> Packet:
    """Wrap one already-built fragment (from fragment_wsc_vendor_payload)
    in the EAP-Expanded/EAPOL stack, same wrapping craft_wsc_msg does."""
    vendor_data = bytes([opcode]) + vendor_fragment
    type_data = WFA_VENDOR_ID + WSC_VENDOR_TYPE + vendor_data
    eap = _eap_packet(EAP_CODE_RESPONSE, identifier, EAP_TYPE_EXPANDED, type_data)
    return _wrap_eapol(bssid, client, _eapol_wrap_eap(eap, version))


@dataclass
class ParsedEap:
    code: int
    identifier: int
    eap_type: int | None
    opcode: int | None  # WSC opcode, only set for Expanded/WSC frames
    flags: int  # WSC flags byte (0 for non-Expanded/non-WSC frames)
    payload: bytes  # TLV blob for WSC_MSG/ACK/NACK; identity string for Identity


def is_frag_ack(parsed: ParsedEap) -> bool:
    """True if parsed is a WSC_FRAG_ACK — the AP/enrollee's request for the
    next fragment of a message we're sending piecewise."""
    return parsed.opcode == WSC_OP_FRAG_ACK


def parse_eap(pkt: Packet) -> ParsedEap | None:
    """Parse an 802.11 data frame's EAPOL/EAP payload; None if not EAP."""
    if pkt.haslayer(EAPOL):
        raw = bytes(pkt.getlayer(EAPOL))
    elif pkt.haslayer(Raw):
        raw = bytes(pkt.getlayer(Raw))
    else:
        return None
    if len(raw) < 4:
        return None
    eapol_type = raw[1]
    if eapol_type != EAPOL_TYPE_EAP_PACKET:
        return None
    eap = raw[4:]
    if len(eap) < 5:
        return None
    code, identifier = eap[0], eap[1]
    eap_type = eap[4]
    body = eap[5:]
    if eap_type == EAP_TYPE_EXPANDED:
        if len(body) < 9:
            return None
        opcode = body[7]
        flags = body[8]
        offset = 9
        if flags & WSC_FLAG_LF:
            if len(body) < offset + 2:
                return None
            offset += 2
        tlv = body[offset:]
        return ParsedEap(code, identifier, eap_type, opcode, flags, tlv)
    return ParsedEap(code, identifier, eap_type, None, 0, body)
