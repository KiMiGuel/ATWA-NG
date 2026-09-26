"""Lightweight raw-bytes 802.11 frame dissection for the scan hot path
(scan.py's process_packet() and the security/WPS/OWE profile parsers it
calls) -- replacing scapy's Packet object model there, the actual
measured CPU cost during continuous scanning (STATUS.md's Performance
section). Frame-CRAFTING for injection (frames.py's craft_*() functions,
used by attacks -- a handful of packets per action, not a hot loop)
stays on scapy unchanged; it was never part of the CPU/fan complaint and
rewriting it would add regression risk to already-live-verified attacks
for no performance benefit.

Uses a small standard-field Radiotap fast path, with dpkt as the correctness
fallback for extended/vendor namespaces (Radiotap has many optional
present-flag fields that are genuinely tedious and error-prone to
hand-parse). Everything past the Radiotap header -- 802.11 MAC header
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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import dpkt.radiotap

TYPE_MGMT = 0
TYPE_CTRL = 1
TYPE_DATA = 2

SUBTYPE_BEACON = 8
SUBTYPE_PROBE_RESP = 5

CAP_PRIVACY = 0x0010

# Standard Radiotap fields through ChannelPlus (bit 15), expressed as
# (present-bit, alignment, byte-width).  The fast path below handles the
# common capture headers without constructing dpkt's nested IEEE80211 object;
# extended/vendor namespaces fall back to dpkt for correctness.
_RADIOTAP_FIELDS = (
    (0, 8, 8),   # TSFT
    (1, 1, 1),   # Flags
    (2, 1, 1),   # Rate
    (3, 2, 4),   # Channel
    (4, 1, 2),   # FHSS
    (5, 1, 1),   # Antenna signal (dBm)
    (6, 1, 1),   # Antenna noise
    (7, 2, 2),   # Lock quality
    (8, 2, 2),   # TX attenuation
    (9, 2, 2),   # dB TX attenuation
    (10, 1, 1),  # dBm TX power
    (11, 1, 1),  # Antenna
    (12, 1, 1),  # dB antenna signal
    (13, 1, 1),  # dB antenna noise
    (14, 2, 2),  # RX flags
    (15, 4, 8),  # ChannelPlus
)
_RADIOTAP_KNOWN_MASK = (1 << 16) - 1


@dataclass(slots=True)
class Frame:
    """One parsed 802.11 frame -- the raw-bytes replacement for a scapy
    Packet in the scan hot path.

    channel_hz: carrier frequency in MHz from the RadioTap CHANNEL field,
        or None. Fallback source for a beacon that omits the DS
        Parameter Set -- without it such an AP reports channel=None and
        cannot be channel-locked.
    body: everything after the MAC header -- information elements for a
    management frame (always a 24-byte header), or the data payload
    (EAPOL, etc.) for a data frame (24-byte header plus QoS Control and
    Addr4 extension fields when present, see dissect()).
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
    addr4: str | None
    to_ds: bool
    from_ds: bool
    sequence_control: int
    signal_dbm: int | None
    channel_hz: int | None
    body: bytes
    raw: bytes


def _mac_str(b: bytes) -> str:
    return b.hex(":")


# Authoritative 802.11 channel -> centre frequency table.
#
# This is a table rather than arithmetic on purpose. 2.4 GHz is 5 MHz steps
# from 2412 with channel 14 stranded at 2484. 5 GHz looks like 20 MHz steps
# but is not: channel 48 is 5245 (not 5240), and channel 144 and 149 are BOTH
# 5745. An earlier version derived the valid set as range(5180, 5826, 20),
# which silently excluded 5745 -- so channel 149, one of the most common
# 5 GHz channels there is, was rejected as implausible and its beacons went
# back to reporting channel=None. Caught by a test asserting the table and
# the arithmetic agree.
_CHANNEL_CENTER_HZ: dict[int, int] = {
    **{ch: 2407 + 5 * ch for ch in range(1, 14)},
    14: 2484,
    36: 5180, 40: 5200, 44: 5220, 48: 5245,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560, 116: 5580,
    120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680, 140: 5720,
    144: 5745, 149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825,
}
_VALID_CENTER_HZ = frozenset(_CHANNEL_CENTER_HZ.values())


def _plausible_hz(value: int) -> bool:
    """True if `value` is a real 802.11 centre frequency."""
    return value in _VALID_CENTER_HZ


def _fast_radiotap_header(raw: bytes) -> tuple[int, int | None, int | None] | None:
    """Return ``(payload_offset, dBm, channel_Hz)`` for standard Radiotap headers.

    dpkt is the correctness fallback for extended/vendor namespaces.  The
    common headers emitted by Scapy and many monitor-mode drivers use only
    the standard fields; parsing those directly avoids constructing dpkt's
    nested IEEE80211 object for every packet in the scan hot path.
    """
    if len(raw) < 8:
        return None
    version, _pad, header_len, present = struct.unpack_from("<BBHI", raw, 0)
    if version != 0:
        return None
    if header_len < 8 or header_len > len(raw):
        return None

    # Unknown *trailing* namespaces must not disqualify the whole header.
    # The fields we need (CHANNEL at bit 3, dBm at bit 5) always come first,
    # so a driver that also sets bit 29/31 -- the mt76x0u does, measured
    # live 2026-09-26 with present=0xa018402a -- still yields a channel.
    # Bailing on any unknown bit is what previously sent every such frame
    # down the dpkt path, which does not expose the channel at all, so those
    # APs reported channel=None.
    #
    # We can only walk as far as the lowest unknown *preceding* field,
    # because an unknown field's width is unknown and alignment after it is
    # therefore undecidable. Everything from there on is simply not read.
    unknown_below = present & ~_RADIOTAP_KNOWN_MASK
    all_fields_known = unknown_below == 0

    # Bit 31 set means Radiotap uses an EXTENDED present mask: a second
    # 4-byte word follows the first, so the fields start at 12, not 8.
    # Getting this wrong shifts every field by 4 bytes -- which silently
    # read the CHANNEL frequency as 0 and the dBm as a nonsense positive
    # value. The mt76x0u sets bit 31 on essentially every frame (measured
    # live 2026-09-26: present=0xa018402a), so this is the common case
    # here, not an edge case.
    offset = 12 if present & (1 << 31) else 8
    signal_dbm = None
    channel_hz = None
    for bit, alignment, width in _RADIOTAP_FIELDS:
        if not present & (1 << bit):
            continue
        # An unknown field at a lower index has an unknown width, so we can
        # no longer trust alignment from here. Stop, keeping whatever we
        # already extracted from the fields that did precede it.
        if unknown_below & ((1 << bit) - 1):
            return header_len, signal_dbm, channel_hz
        padding = (-offset) % alignment
        offset += padding
        if offset + width > len(raw):
            return None
        if bit == 5:
            signal_dbm = struct.unpack_from("<b", raw, offset)[0]
        elif bit == 3:
            # Radiotap's CHANNEL field is nominally flags(1) | frequency(2
            # LE) | [max(1) antenna(1)], but drivers disagree on the order
            # and scapy -- which everything WiFi-adjacent is validated
            # against -- reads the 2-byte frequency FIRST. Measured on the
            # mt76x0u 2026-09-26: the field bytes were `6c 09 a0 00`,
            # giving 0x096c = 2412 (correct) when read at +0 and 0xa009 =
            # 40969 (nonsense) when read at +1 the spec way.
            #
            # So try both offsets and keep whichever is a real 802.11
            # centre frequency. That is driver-agnostic and cannot be
            # fooled by a flags byte that happens to look plausible.
            first = struct.unpack_from("<H", raw, offset)[0]
            second = struct.unpack_from("<H", raw, offset + 1)[0]
            if _plausible_hz(first):
                channel_hz = first
            elif _plausible_hz(second):
                channel_hz = second
            else:
                channel_hz = None
        offset += width
    if all_fields_known and offset != header_len:
        return None
    return header_len, signal_dbm, channel_hz


def dissect(raw: bytes) -> Frame | None:
    """Parse one captured frame (RadioTap header onward). Returns None
    if the frame is too short/malformed to contain a full 802.11 MAC
    header, or if the RadioTap header itself is malformed -- callers
    should skip it, same as scapy silently producing an unusable
    Packet for a truncated capture."""
    try:
        fast_header = _fast_radiotap_header(raw)
        if fast_header is not None:
            mac_start, signal_dbm, channel_hz = fast_header
        else:
            rtap = dpkt.radiotap.Radiotap(raw)
            mac_start = rtap.length
            signal_dbm = rtap.ant_sig.db if getattr(rtap, "ant_sig_present", False) else None
            # dpkt exposes the channel as a (freq, flags, channel) tuple on
            # different versions, so read it defensively and only trust it
            # when a usable MHz frequency is present.
            channel_hz = None
            ch = getattr(rtap, "ch", None)
            if isinstance(ch, (tuple, list)) and ch:
                freq = ch[0]
                if isinstance(freq, int) and freq:
                    channel_hz = freq
            elif isinstance(getattr(rtap, "ch_freq", None), int):
                channel_hz = rtap.ch_freq or None
    except Exception:  # noqa: BLE001 - any malformed radiotap header means "skip this frame"
        return None

    mac = raw[mac_start:]
    if len(mac) < 24:
        return None
    frame_control = struct.unpack_from("<H", mac, 0)[0]
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    sequence_control = struct.unpack_from("<H", mac, 22)[0]

    # Data-frame MAC headers are NOT always 24 bytes: QoS data frames
    # (subtype bit 3 -- the norm on WPA2 networks, which send EAPOL as
    # QoS Data) carry a 2-byte QoS Control field, and 4-addr WDS frames
    # (ToDS+FromDS both set) carry a 6-byte Addr4. Slicing the body at a
    # fixed 24 shifted every such payload left, so _eapol_payload()'s
    # LLC/SNAP match silently missed nearly all real handshake traffic.
    to_ds = bool(mac[1] & 0x01)
    from_ds = bool(mac[1] & 0x02)
    header_len = 24
    if frame_type == TYPE_DATA:
        if to_ds and from_ds:
            header_len += 6  # Addr4 (WDS); sequence control stays at offset 22
        if subtype & 0x8:
            header_len += 2  # QoS Control
    if len(mac) < header_len:
        return None

    addr4 = _mac_str(mac[24:30]) if (to_ds and from_ds) else None

    return Frame(
        frame_type=frame_type,
        subtype=subtype,
        addr1=_mac_str(mac[4:10]),
        addr2=_mac_str(mac[10:16]),
        addr3=_mac_str(mac[16:22]),
        addr4=addr4,
        to_ds=to_ds,
        from_ds=from_ds,
        sequence_control=sequence_control,
        signal_dbm=signal_dbm,
        channel_hz=channel_hz,
        body=mac[header_len:],
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


def ssid_of(frame: Frame, ies: Iterable[tuple[int, bytes]] | None = None) -> str | None:
    """SSID element (ID 0) from a beacon/probe-response frame, or None
    for hidden/missing SSIDs. Real SSIDs aren't guaranteed UTF-8 --
    fall back to latin-1 (never fails) rather than always landing on
    U+FFFD replacement chars."""
    for ie_id, info in (ies if ies is not None else walk_ies(frame.body[12:])):
        if ie_id == 0:
            try:
                return info.decode("utf-8") or None
            except UnicodeDecodeError:
                return info.decode("latin-1") or None
    return None


def _channel_from_hz(hz: int) -> int | None:
    """Centre frequency in MHz -> 802.11 channel number, or None.

    5745 maps to 149, preferring the UNII-3 channel number over 144: both
    share the frequency but 149 is the one that appears in normal 5 GHz
    operation, and radio.py's CHANNELS_5GHZ only lists 149.
    """
    for channel, center in _CHANNEL_CENTER_HZ.items():
        if center == hz:
            if hz == 5745:
                return 149
            return channel
    return None


def channel_of(frame: Frame, ies: Iterable[tuple[int, bytes]] | None = None) -> int | None:
    """Channel for a beacon/probe-response, or None.

    Prefers the DS Parameter Set element (ID 3), which is what the AP itself
    advertises. Falls back to the RadioTap CHANNEL frequency, which is what
    the capture interface actually heard the frame on.

    The fallback is not a nicety. Measured live on 2026-09-26: of 469
    beacons captured on one channel, 49 (10.4%) carried no DS Parameter Set
    at all, and every one of them had a usable RadioTap frequency. Those
    APs previously reported channel=None, which meant the GUI could not
    channel-lock them and PINCER could not park a radio on them.
    """
    for ie_id, info in (ies if ies is not None else walk_ies(frame.body[12:])):
        if ie_id == 3 and info:
            return info[0]
    if frame.channel_hz:
        return _channel_from_hz(frame.channel_hz)
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
