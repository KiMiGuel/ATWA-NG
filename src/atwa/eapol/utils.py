"""EAPOL-Key parsing -- the single implementation for the whole codebase.

Offsets are from the EAPOL Protocol Version byte (IEEE 802.11-2024
12.7.2; field table corroborated against Wireshark's packet-eapol.c and
hostap's wpa.h):

    0 version      1 type        2 len(2)     4 descriptor_type
    5 key_info(2)  7 key_len(2)  9 replay(8) 17 nonce(32)
   49 key_iv(16)  65 key_rsc(8) 73 reserved(8) 81 MIC  97 key_data_len(2)

Two things this module exists to get right, both of which the previous
split implementations (dissect.py on Frame, frames.py on scapy Packet)
got wrong:

MIC width is not fixed. The SHA-384 / Suite-B AKM family (AKMs 12, 13,
19, 20, 22, 23 -- the WPA3/SAE ones) carries a 24-byte MIC, moving
key_data_len to offset 105. Assuming 16 bytes reads every such frame's
"key data" 8 bytes early, inside the MIC. Width comes from the declared
body length.

EAPOL-Key is a subtype of EAPOL. Type 0 (EAP-Packet), 1 (Start) and 2
(Logoff) are EAPOL but carry no key descriptor; reading key_info out of
their payload fabricates a handshake message. Everything here requires
type 3 and a real key descriptor type.
"""

from __future__ import annotations

from dataclasses import dataclass

# EAPOL Packet Type (IEEE 802.1X 4.2).
EAPOL_TYPE_PACKET = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3

# Key Descriptor Type (IEEE 802.11-2024 Table 12-7). 0 is reserved and
# anything above 254 is unassigned, so both are rejected rather than
# trusted -- a garbage descriptor type means the offsets below do not
# describe the bytes actually present.
DESC_TYPE_RESERVED = 0
DESC_TYPE_8021X = 1  # WPA1: HMAC-SHA1 + TKIP
DESC_TYPE_RSN = 2  # WPA2/WPA3
DESC_TYPE_TKIP = 3
DESC_TYPE_WPA = 254  # legacy WPA/WEP

_VALID_DESC_TYPES = frozenset(
    (DESC_TYPE_8021X, DESC_TYPE_RSN, DESC_TYPE_TKIP, DESC_TYPE_WPA)
)

# Key Information bits (IEEE 802.11-2024 Fig 12-36).
KEY_INFO_VERSION_MASK = 0x0007
KEY_INFO_PAIRWISE = 0x0008
KEY_INFO_INSTALL = 0x0040
KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200
KEY_INFO_ERROR = 0x0400
KEY_INFO_REQUEST = 0x0800

# Fixed offsets from the Protocol Version byte.
_OFF_TYPE = 1
_OFF_LEN = 2
_OFF_DESC_TYPE = 4
_OFF_KEY_INFO = 5
_OFF_REPLAY = 9
_OFF_NONCE = 17
_OFF_MIC = 81
_OFF_KEY_DATA_LEN_16 = 97
_OFF_KEY_DATA_16 = 99
_OFF_KEY_DATA_LEN_24 = 105
_OFF_KEY_DATA_24 = 107

# Body overhead (everything but Key Data) per MIC width.
_BODY_OVERHEAD_16 = 95
_BODY_OVERHEAD_24 = 103

_NONCE_LEN = 32
_ZERO = bytes(32)

# 802.2 LLC/SNAP encapsulation, ethertype 0x888E (802.1X). Over-the-air
# data frames carrying EAPOL always have this 8-byte header first.
_LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


@dataclass(frozen=True)
class EapolKey:
    """One parsed EAPOL-Key frame.

    nonce is ANonce for M1/M3 and SNonce for M2/M4 (all-zero on M3/M4 of
    some stacks). mic is empty when the frame carries none -- M1 zeroes
    the field, and WPA legacy M4 may omit the descriptor tail entirely.
    """

    key_info: int
    descriptor_type: int
    key_version: int
    replay_counter: int
    nonce: bytes
    mic: bytes
    key_data: bytes
    raw: bytes

    @property
    def mic_len(self) -> int:
        return len(self.mic)

    @property
    def is_rsn(self) -> bool:
        """True for the RSN descriptor type (WPA2/WPA3)."""
        return self.descriptor_type == DESC_TYPE_RSN

    @property
    def ack(self) -> bool:
        return bool(self.key_info & KEY_INFO_ACK)

    @property
    def mic_set(self) -> bool:
        return bool(self.key_info & KEY_INFO_MIC)

    @property
    def secure(self) -> bool:
        return bool(self.key_info & KEY_INFO_SECURE)

    @property
    def install(self) -> bool:
        return bool(self.key_info & KEY_INFO_INSTALL)

    @property
    def pairwise(self) -> bool:
        return bool(self.key_info & KEY_INFO_PAIRWISE)


def _strip_llc_snap(data: bytes) -> bytes:
    """Drop an 802.2 LLC/SNAP header when one is present."""
    return data[len(_LLC_SNAP_EAPOL):] if data[:8] == _LLC_SNAP_EAPOL else data


def _plausible_eapol_header(data: bytes) -> bool:
    """Cheap shape check before any offset arithmetic: version 0-2 and
    type 0-3. The full type/descriptor validation happens in
    parse_eapol_key; this only rejects obviously-not-EAPOL data so a
    random payload is never sliced at fixed offsets."""
    return len(data) >= 4 and data[0] <= 2 and data[1] <= EAPOL_TYPE_KEY


def _mic_width(declared_body_len: int, available: int) -> int:
    """MIC width in bytes, 16 or 24.

    Derived from the declared body length (body = everything but Key
    Data), so it does not depend on the frame having been captured
    whole. A 24-byte-MIC frame is only chosen when a 16-byte reading
    would run past the bytes actually present -- otherwise a truncated
    SHA-384 frame would still report its true MIC length.
    """
    if declared_body_len >= _BODY_OVERHEAD_24 and available >= _OFF_KEY_DATA_24:
        return 24
    return 16


def parse_eapol_key(data: bytes) -> EapolKey | None:
    """Parse an EAPOL-Key PDU (or an 802.11 data frame body carrying
    one), or None if it is not a well-formed EAPOL-Key frame.

    Accepts the PDU with or without a leading LLC/SNAP header, so
    callers holding either a dissect.Frame.body or the bytes of a Scapy
    Packet can share this one parser.
    """
    pdu = _strip_llc_snap(data)
    if not _plausible_eapol_header(pdu):
        return None
    if pdu[1] != EAPOL_TYPE_KEY:
        return None

    desc_type = pdu[_OFF_DESC_TYPE] if len(pdu) > _OFF_DESC_TYPE else -1
    if desc_type not in _VALID_DESC_TYPES:
        return None
    if len(pdu) < _OFF_KEY_INFO + 2:
        return None

    key_info = int.from_bytes(pdu[_OFF_KEY_INFO:_OFF_KEY_INFO + 2], "big")
    declared_body_len = int.from_bytes(pdu[_OFF_LEN:_OFF_LEN + 2], "big")
    available = len(pdu)
    mic_len = _mic_width(declared_body_len, available)

    # Everything before the MIC is fixed-width for both MIC widths.
    if available < _OFF_MIC + mic_len:
        return None

    key_data_len_off = _OFF_KEY_DATA_LEN_16 if mic_len == 16 else _OFF_KEY_DATA_LEN_24
    key_data_off = _OFF_KEY_DATA_16 if mic_len == 16 else _OFF_KEY_DATA_24
    if available < key_data_len_off + 2:
        return None
    key_data_len = int.from_bytes(pdu[key_data_len_off:key_data_len_off + 2], "big")
    key_data = pdu[key_data_off:key_data_off + key_data_len]

    replay = pdu[_OFF_REPLAY:_OFF_REPLAY + 8]
    nonce = pdu[_OFF_NONCE:_OFF_NONCE + _NONCE_LEN]

    return EapolKey(
        key_info=key_info,
        descriptor_type=desc_type,
        key_version=key_info & KEY_INFO_VERSION_MASK,
        replay_counter=int.from_bytes(replay, "big"),
        nonce=nonce,
        mic=pdu[_OFF_MIC:_OFF_MIC + mic_len],
        key_data=key_data,
        raw=pdu,
    )


def is_eapol(data: bytes) -> bool:
    """True if the data carries a well-formed EAPOL-Key frame.

    Narrower than "is this EAPOL": EAP-Packet/Start/Logoff are EAPOL but
    not EAPOL-Key, and only the Key subtype has the key descriptor every
    offset here depends on.
    """
    return parse_eapol_key(data) is not None


def eapol_key_info(data: bytes) -> tuple[bool, bool] | None:
    """(mic_set, ack_set) from a WPA key EAPOL frame, else None.

    Kept as the compatibility surface for the two flag bits callers
    branch on. Prefer parse_eapol_key() when anything else is needed.
    """
    key = parse_eapol_key(data)
    if key is None:
        return None
    return key.mic_set, key.ack


def extract_nonce(data: bytes) -> bytes | None:
    """The 32-byte key nonce (ANonce on M1/M3, SNonce on M2/M4), or None
    when absent or zero -- all-zero is how M3/M4 and GTK frames mark a
    nonce they did not send."""
    key = parse_eapol_key(data)
    if key is None or key.nonce == _ZERO:
        return None
    return key.nonce


def extract_mic(data: bytes) -> bytes | None:
    """The Key MIC (16 or 24 bytes), or None when absent or zero.

    Width follows the descriptor's AKM family, so a WPA3/SAE frame
    yields its full 24 bytes rather than a 16-byte prefix.
    """
    key = parse_eapol_key(data)
    if key is None or not key.mic or key.mic == bytes(len(key.mic)):
        return None
    return key.mic


def message_number(data: bytes) -> int | None:
    """Classify a pairwise EAPOL-Key frame as handshake message 1-4.

    Follows Wireshark's packet-eapol.c: the Key Information bits decide
    M1/M2/M3/M4 for RSN, while legacy WPA frames -- where SECURE is not
    set on M4 -- are told apart by the replay counter instead (zero on
    M2, non-zero once M3 has bumped it).

    Group (GTK rekey) frames, and Request/Error frames, return None:
    neither belongs to the pairwise handshake, and folding a group M1
    into the pairwise numbering produces captures that look complete and
    verify as empty.
    """
    key = parse_eapol_key(data)
    if key is None or not key.pairwise:
        return None
    if key.key_info & (KEY_INFO_REQUEST | KEY_INFO_ERROR):
        return None

    ack, mic, secure = key.ack, key.mic_set, key.secure

    if ack and not mic:
        return 1
    if ack and mic:
        return 3
    if not ack and mic:
        # SECURE alone separates M2 from M4 for every descriptor except
        # legacy WPA/WEP (254), where it is absent on both and the replay
        # counter decides instead. Types 1 and 3 are WPA1 802.1X and follow
        # the same rule as RSN -- notably a WPA1 M4 sets SECURE, so routing
        # them down the legacy path would misread it as M2.
        if key.descriptor_type == DESC_TYPE_WPA:
            return 4 if key.replay_counter else 2
        return 4 if secure else 2
    return None