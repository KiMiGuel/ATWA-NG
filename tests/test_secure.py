"""secure.py: security-profile parsing and WPS IE extraction."""
from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from scapy.packet import Packet, Raw

from atwa.frames import craft_beacon, craft_rsn_ie
from atwa.scan import AccessPoint
from atwa.secure import (
    OWE_TRANSITION_OUI_TYPE,
    owe_transition_info,
    recommend_attack,
    security_profile,
    wps_profile,
)
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


# --- security_profile(): had zero coverage before this pass -------------------


def test_security_profile_open():
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="OpenNet", privacy=False)
    assert security_profile(pkt) == {"security": "open", "pmf": "none"}


def test_security_profile_wpa2_psk():
    rsn = craft_rsn_ie(akms=[2])
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="Home", privacy=True, extra_ies=[rsn])
    profile = security_profile(pkt)
    assert profile["security"] == "WPA2"


def test_security_profile_wpa3_sae():
    rsn = craft_rsn_ie(akms=[8])
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="Home", privacy=True, extra_ies=[rsn])
    profile = security_profile(pkt)
    assert profile["security"] == "WPA3"


def test_security_profile_wpa3_transition():
    rsn = craft_rsn_ie(akms=[2, 8])
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="Home", privacy=True, extra_ies=[rsn])
    profile = security_profile(pkt)
    assert profile["security"] == "transition"


def test_security_profile_owe_is_not_misclassified_as_wpa2():
    """Regression test: AKM 18 (OWE / Enhanced Open) was never checked at
    all, so every OWE beacon silently fell through to "WPA2" -- a real
    network with no PSK at all being reported as PSK-crackable."""
    rsn = craft_rsn_ie(akms=[18])
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="OWENet", privacy=True, extra_ies=[rsn])
    profile = security_profile(pkt)
    assert profile["security"] == "OWE"
    assert profile["security"] != "WPA2"


def test_security_profile_owe_with_pmf_required():
    rsn = craft_rsn_ie(akms=[18], mfpr=True)
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="OWENet", privacy=True, extra_ies=[rsn])
    profile = security_profile(pkt)
    assert profile["security"] == "OWE"
    assert profile["pmf"] == "required"


# --- owe_transition_info(): no coverage before this pass -----------------


def _beacon_with_owe_transition_ie(bssid: str, ssid: str) -> Packet:
    """Build a minimal beacon carrying an OWE Transition Mode vendor IE."""
    bssid_bytes = bytes(int(x, 16) for x in bssid.split(":"))
    ssid_bytes = ssid.encode("utf-8")
    ie_body = OWE_TRANSITION_OUI_TYPE + bssid_bytes + bytes([len(ssid_bytes)]) + ssid_bytes
    ie = bytes([221, len(ie_body)]) + ie_body
    return RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon() / Raw(load=ie)


def test_owe_transition_info_extracts_bssid_and_ssid():
    pkt = _beacon_with_owe_transition_ie("11:22:33:44:55:66", "HomeOpen")
    assert owe_transition_info(pkt) == {"bssid": "11:22:33:44:55:66", "ssid": "HomeOpen"}


def test_owe_transition_info_returns_none_when_absent():
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon()
    assert owe_transition_info(pkt) is None


def test_owe_transition_info_handles_empty_ssid():
    pkt = _beacon_with_owe_transition_ie("11:22:33:44:55:66", "")
    assert owe_transition_info(pkt) == {"bssid": "11:22:33:44:55:66", "ssid": None}


def test_owe_transition_info_ignores_truncated_ie():
    # body shorter than the minimum 7 bytes (bssid + ssid-len byte) -- a
    # malformed/RF-noise frame, must not raise or return garbage.
    ie_body = OWE_TRANSITION_OUI_TYPE + b"\x11\x22\x33"  # only 3 of 6 bssid bytes
    ie = bytes([221, len(ie_body)]) + ie_body
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff") / Dot11Beacon() / Raw(load=ie)
    assert owe_transition_info(pkt) is None


# --- recommend_attack(): OWE branches, zero coverage before this pass ----


def test_recommend_attack_owe_with_transition_pair_recommends_downgrade():
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff", security="OWE",
        owe_transition_bssid="11:22:33:44:55:66", owe_transition_ssid="HomeOpen",
    )
    result = recommend_attack(ap)
    assert result["attack"] == "owe_downgrade"
    assert "HomeOpen" in result["reason"]
    assert "11:22:33:44:55:66" in result["reason"]


def test_recommend_attack_owe_without_transition_pair_recommends_none():
    ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", security="OWE")
    result = recommend_attack(ap)
    assert result["attack"] == "none"
    assert "transition" in result["reason"].lower()
