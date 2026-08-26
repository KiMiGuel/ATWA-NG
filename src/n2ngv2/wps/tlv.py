"""WSC (Wi-Fi Simple Config) TLV attribute encode/decode and constants.

Attribute IDs, message-type bytes, and the EAP-Expanded vendor triple are
taken verbatim from wpa_supplicant's wps_defs.h (the reference
implementation), not reconstructed from memory. See STATUS.md "Research
notes" for provenance.
"""

from __future__ import annotations

# EAP Expanded Type (RFC 3748 §5.7): vendor ID 00:37:2A (WFA, 14122
# decimal), vendor type 0x00000001 (SimpleConfig).
EAP_TYPE_EXPANDED = 254
WFA_VENDOR_ID = b"\x00\x37\x2a"
WSC_VENDOR_TYPE = b"\x00\x00\x00\x01"

# EAP identity string a WSC registrar must present.
WSC_REGISTRAR_IDENTITY = b"WFA-SimpleConfig-Registrar-1-0"

# --- WSC message type (ATTR_MSG_TYPE value) ---
WPS_M1 = 0x04
WPS_M2 = 0x05
WPS_M2D = 0x06
WPS_M3 = 0x07
WPS_M4 = 0x08
WPS_M5 = 0x09
WPS_M6 = 0x0A
WPS_M7 = 0x0B
WPS_M8 = 0x0C
WPS_WSC_ACK = 0x0D
WPS_WSC_NACK = 0x0E
WPS_WSC_DONE = 0x0F

# --- WSC attribute type IDs ---
ATTR_ASSOC_STATE = 0x1002
ATTR_AUTH_TYPE_FLAGS = 0x1004
ATTR_AUTHENTICATOR = 0x1005
ATTR_CONFIG_METHODS = 0x1008
ATTR_CONFIG_ERROR = 0x1009
ATTR_CONN_TYPE_FLAGS = 0x100D
ATTR_CRED = 0x100E
ATTR_DEV_PASSWORD_ID = 0x1012
ATTR_DEVICE_NAME = 0x1011
ATTR_ENCR_TYPE_FLAGS = 0x1010
ATTR_ENCR_SETTINGS = 0x1018
ATTR_E_HASH1 = 0x1014
ATTR_E_HASH2 = 0x1015
ATTR_E_SNONCE1 = 0x1016
ATTR_E_SNONCE2 = 0x1017
ATTR_KEY_WRAP_AUTH = 0x101E
ATTR_MAC_ADDR = 0x1020
ATTR_MANUFACTURER = 0x1021
ATTR_MSG_TYPE = 0x1022
ATTR_MODEL_NAME = 0x1023
ATTR_MODEL_NUMBER = 0x1024
ATTR_NETWORK_KEY = 0x1027
ATTR_ENROLLEE_NONCE = 0x101A
ATTR_OS_VERSION = 0x102D
ATTR_PUBLIC_KEY = 0x1032
ATTR_REGISTRAR_NONCE = 0x1039
ATTR_RF_BANDS = 0x103C
ATTR_R_HASH1 = 0x103D
ATTR_R_HASH2 = 0x103E
ATTR_R_SNONCE1 = 0x103F
ATTR_R_SNONCE2 = 0x1040
ATTR_SERIAL_NUMBER = 0x1042
ATTR_SSID = 0x1045
ATTR_WPS_STATE = 0x1044
ATTR_UUID_E = 0x1047
ATTR_UUID_R = 0x1048
ATTR_PRIMARY_DEV_TYPE = 0x1054
ATTR_AP_SETUP_LOCKED = 0x1057
ATTR_VERSION = 0x104A
ATTR_VENDOR_EXT = 0x1049
ATTR_REQUEST_TYPE = 0x103A

# WFA vendor extension sub-element carrying the WSC2.0 version marker.
WFA_ELEM_VERSION2 = 0x00
WPS_VERSION2 = 0x20

# Microsoft OUI + WPS vendor type 4 — the 4-byte prefix of a WPS
# vendor-specific 802.11 IE (element ID 221), whether it's the AP
# advertising WPS in a beacon or an enrollee marking WPS intent in an
# association request. Shared here so beacon-side detection (secure.py)
# and assoc-request crafting (messages.py) use the same bytes.
WPS_VENDOR_OUI_TYPE = b"\x00\x50\xf2\x04"


def encode_tlv(attr_type: int, value: bytes) -> bytes:
    """Encode one WSC attribute: type(2) + length(2) + value, big-endian."""
    return attr_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def encode_tlvs(*pairs: tuple[int, bytes]) -> bytes:
    """Encode and concatenate several (attr_type, value) pairs in order."""
    return b"".join(encode_tlv(t, v) for t, v in pairs)


def decode_tlvs(data: bytes) -> dict[int, bytes]:
    """Decode a byte string of concatenated WSC TLVs into {type: value}.

    Ignores a duplicate attribute's later occurrence (WSC messages don't
    legitimately repeat a type); malformed trailing bytes stop parsing.
    """
    attrs: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        attr_type = int.from_bytes(data[pos : pos + 2], "big")
        length = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + length > len(data):
            break
        attrs.setdefault(attr_type, data[pos : pos + length])
        pos += length
    return attrs
