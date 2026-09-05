"""Lightweight raw-bytes 802.11 frame dissection for the scan hot path
(scan.py's process_packet() and the security/WPS/OWE profile parsers it
calls) -- replacing scapy's Packet object model there, the actual
measured CPU cost during continuous scanning (STATUS.md's Performance
section). Frame-CRAFTING for injection (frames.py's craft_*() functions,
used by attacks -- a handful of packets per action, not a hot loop)
stays on scapy unchanged; it was never part of the CPU/fan complaint and
rewriting it would add regression risk to already-live-verified attacks
for no performance benefit.

Uses dpkt for Radiotap header parsing only (its most reliable piece --
Radiotap has many optional present-flag fields that are genuinely
tedious and error-prone to hand-parse, and dpkt's header-length/
antenna-signal extraction checked out correctly against known-good
wire bytes). Everything past the Radiotap header -- 802.11 MAC header
fields, beacon capability, information elements -- is a small,
purpose-built parser instead of dpkt's higher-level IEEE80211/Beacon
classes, for two confirmed reasons:

1. dpkt.ieee80211.IEEE80211.Beacon.unpack() has a real bug: it
   byte-swaps timestamp and interval but NOT capability, so the
   privacy/PMF bits come out wrong. Verified against scapy's own
   emitted wire bytes for a "privacy" beacon: the actual bytes on the
   wire are 0x10 0x00 -- correctly little-endian 0x0010, the standard
   802.11 privacy bit -- but dpkt's own `beacon.capability` reports
   4096 (0x1000), the big-endian misread of those same two bytes.
2. dpkt's automatic `Radiotap.data` -> `IEEE80211` -> subtype-specific
   class dissection chain raises on frames that don't fully match its
   expected fixed-field layout (confirmed: a malformed/truncated frame
   crashes construction outright, not a partial/best-effort object) --
   fragile for a continuous real-world capture loop that will see RF
   noise and partial frames regularly.

RSN/WPA1/WPS/OWE-Transition-mode information-element parsing in
secure.py already worked on raw frame bytes before this change (never
depended on scapy's object model) and needs no changes here beyond
taking `Frame.raw`/`Frame.body` instead of `bytes(pkt)`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

import dpkt.radiotap

TYPE_MGMT = 0
TYPE_CTRL = 1
TYPE_DATA = 2

SUBTYPE_BEACON = 8
SUBTYPE_PROBE_RESP = 5

CAP_PRIVACY = 0x0010


@dataclass
class Frame:
    """One parsed 802.11 frame -- the raw-bytes replacement for a scapy
    Packet in the scan hot path.

    body: everything after the fixed 24-byte MAC header -- information
    elements for a management frame, or the data payload (EAPOL, etc.)
    for a data frame.
    raw: the full original frame bytes (RadioTap header onward) --
    RSN/WPA1/WPS/OWE-Transition scanning in secure.py searches this
    directly, same as it already searched `bytes(pkt)` before this
    change.
    """

    frame_type: int
    subtype: int
    addr1: str
    addr2: str
    addr3: str
    sequence_control: int
    signal_dbm: int | None
    body: bytes
    raw: bytes


def _mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def dissect(raw: bytes) -> Frame | None:
    """Parse one captured frame (RadioTap header onward). Returns None
    if the frame is too short/malformed to contain a full 802.11 MAC
    header, or if the RadioTap header itself is malformed -- callers
    should skip it, same as scapy silently producing an unusable
    Packet for a truncated capture."""
    try:
        rtap = dpkt.radiotap.Radiotap(raw)
        mac_start = rtap.length
        signal_dbm = rtap.ant_sig.db if getattr(rtap, "ant_sig_present", False) else None
    except Exception:  # noqa: BLE001 - any malformed radiotap header means "skip this frame"
        return None

    mac = raw[mac_start:]
    if len(mac) < 24:
        return None
    frame_control = struct.unpack_from("<H", mac, 0)[0]
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    sequence_control = struct.unpack_from("<H", mac, 22)[0]
    return Frame(
        frame_type=frame_type,
        subtype=subtype,
        addr1=_mac_str(mac[4:10]),
        addr2=_mac_str(mac[10:16]),
        addr3=_mac_str(mac[16:22]),
        sequence_control=sequence_control,
        signal_dbm=signal_dbm,
        body=mac[24:],
        raw=raw,
    )


def is_beacon_or_probe_resp(frame: Frame) -> bool:
    return frame.frame_type == TYPE_MGMT and frame.subtype in (SUBTYPE_BEACON, SUBTYPE_PROBE_RESP)


def beacon_capability(frame: Frame) -> int:
    """Capability field from a beacon/probe-response body -- the 2
    bytes right after the 8-byte timestamp + 2-byte interval fixed
    fields. Correctly read little-endian; see the module docstring for
    why dpkt's own equivalent field can't be trusted as-is."""
    if len(frame.body) < 12:
        return 0
    return struct.unpack_from("<H", frame.body, 10)[0]


def walk_ies(body_after_fixed_fields: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (id, info_bytes) for each information element in a
    beacon/probe-response body, starting right after the 12-byte
    timestamp+interval+capability fixed fields."""
    buf = body_after_fixed_fields
    while len(buf) >= 2:
        ie_id = buf[0]
        ie_len = buf[1]
        info = buf[2 : 2 + ie_len]
        if len(info) < ie_len:
            return  # truncated frame -- stop rather than yield a short/garbage IE
        yield ie_id, info
        buf = buf[2 + ie_len :]


def ssid_of(frame: Frame) -> str | None:
    """SSID element (ID 0) from a beacon/probe-response frame, or None
    for hidden/missing SSIDs. Real SSIDs aren't guaranteed UTF-8 --
    fall back to latin-1 (never fails) rather than always landing on
    U+FFFD replacement chars."""
    for ie_id, info in walk_ies(frame.body[12:]):
        if ie_id == 0:
            try:
                return info.decode("utf-8") or None
            except UnicodeDecodeError:
                return info.decode("latin-1") or None
    return None


def channel_of(frame: Frame) -> int | None:
    """DS Parameter Set element (ID 3) channel, or None."""
    for ie_id, info in walk_ies(frame.body[12:]):
        if ie_id == 3 and info:
            return info[0]
    return None


_LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"  # 802.2 LLC/SNAP, ethertype 0x888E (802.1X)


def _eapol_payload(frame: Frame) -> bytes | None:
    """The EAPOL payload of a data frame's body, or None if it doesn't
    look like one.

    Real over-the-air 802.11 data frames carrying EAPOL have an 8-byte
    LLC/SNAP encapsulation header first (802.2 LLC/SNAP, ethertype
    0x888E) -- skip it when present. When it isn't (a simplified test
    fixture attaching EAPOL directly after the MAC header, which is
    how this project's existing test suite builds them, relying on
    scapy's own layer-tree search rather than a fixed byte offset),
    fall back to treating the body as EAPOL only if it actually looks
    like a plausible EAPOL header (version 1-3, type 0-3) -- avoids
    false-positiving on arbitrary data frame payloads that simply lack
    the LLC header."""
    body = frame.body
    if body[:8] == _LLC_SNAP_EAPOL:
        return body[8:]
    if len(body) >= 4 and body[0] in (1, 2, 3) and body[1] in (0, 1, 2, 3):
        return body
    return None


def is_eapol(frame: Frame) -> bool:
    """True if a data frame's body carries an EAPOL (802.1X) payload."""
    return _eapol_payload(frame) is not None


def eapol_key_info(frame: Frame) -> tuple[bool, bool] | None:
    """Return (mic_set, ack_set) from a WPA key EAPOL frame, else None.

    The two flag bits identify handshake messages: M1 has ack+!mic,
    M2 has mic+!ack, M3 has ack+mic (with install), M4 has mic+!ack."""
    eapol = _eapol_payload(frame)
    if eapol is None:
        return None
    # EAPOL: [version(1)][type(1)][length(2)][descriptor_type(1)][key_info(2, big-endian)]...
    key_frame = eapol[4:]
    if len(key_frame) < 3:
        return None
    key_info = int.from_bytes(key_frame[1:3], "big")
    mic_set = bool(key_info & 0x0100)
    ack_set = bool(key_info & 0x0080)
    return mic_set, ack_set
