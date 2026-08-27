"""secure.py: security-profile parsing and WPS IE extraction."""
from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from scapy.packet import Packet, Raw

from atwa.secure import wps_profile
from atwa.wps.tlv import (
    ATTR_AP_SETUP_LOCKED,
    ATTR_DEVICE_NAME,
    ATTR_MANUFACTURER,
    ATTR_MODEL_NAME,
    ATTR_MODEL_NUMBER,
    WPS_VENDOR_OUI_TYPE,
    encode_tlvs,
)


def _beacon_with_wps_ie(tlv_blob: bytes, locked: bool = False) -> Packet:
    """Build a minimal beacon carrying a WPS vendor-specific IE."""
    if locked:
        # Prepend the lock flag so the caller's blob can still carry other attrs.
        tlv_blob = encode_tlvs((ATTR_AP_SETUP_LOCKED, b"\x01")) + tlv_blob
    ie_body = WPS_VENDOR_OUI_TYPE + tlv_blob
    ie = bytes([221, len(ie_body)]) + ie_body
    return RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon() / Raw(load=ie)


def test_wps_profile_returns_none_when_no_wps_ie():
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon()
    assert wps_profile(pkt) is None


def test_wps_profile_detects_enabled_state():
    pkt = _beacon_with_wps_ie(encode_tlvs((ATTR_AP_SETUP_LOCKED, b"\x00")))
    profile = wps_profile(pkt)
    assert profile is not None
    assert profile["state"] == "enabled"


def test_wps_profile_detects_locked_state():
    pkt = _beacon_with_wps_ie(encode_tlvs((ATTR_AP_SETUP_LOCKED, b"\x01")))
    profile = wps_profile(pkt)
    assert profile is not None
    assert profile["state"] == "locked"


def test_wps_profile_extracts_device_metadata():
    tlvs = encode_tlvs(
        (ATTR_MANUFACTURER, b"ExampleInc"),
        (ATTR_MODEL_NAME, b"Model-X"),
        (ATTR_MODEL_NUMBER, b"1234"),
        (ATTR_DEVICE_NAME, b"Living Room AP"),
    )
    pkt = _beacon_with_wps_ie(tlvs)
    profile = wps_profile(pkt)
    assert profile == {
        "state": "enabled",
        "manufacturer": "ExampleInc",
        "model_name": "Model-X",
        "model_number": "1234",
        "device_name": "Living Room AP",
    }


def test_wps_profile_ignores_missing_metadata():
    pkt = _beacon_with_wps_ie(encode_tlvs((ATTR_MANUFACTURER, b"OnlyMfg")))
    profile = wps_profile(pkt)
    assert profile is not None
    assert profile["state"] == "enabled"
    assert profile["manufacturer"] == "OnlyMfg"
    assert profile["model_name"] is None
    assert profile["model_number"] is None
    assert profile["device_name"] is None
