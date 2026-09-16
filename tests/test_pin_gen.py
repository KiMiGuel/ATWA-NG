"""wps/pin_gen.py: get_oui_pins() -- the known-default/MAC-derived PIN
candidates tried before attacks/wps.py's full 0000-9999 bruteforce sweep
(Phase 4.6, v2.4)."""
from __future__ import annotations

from atwa.wps.pin_gen import DEFAULT_WPS_PIN, WPSpin, get_oui_pins

BSSID = "aa:bb:cc:dd:ee:ff"


def test_get_oui_pins_always_includes_default_pin_first():
    pins = get_oui_pins(BSSID, ssid="SomeRandomNetwork")
    assert pins[0] == DEFAULT_WPS_PIN


def test_get_oui_pins_deduplicates():
    pins = get_oui_pins(BSSID, ssid="INFINITUM1234")
    assert len(pins) == len(set(pins))


def test_get_oui_pins_matches_mexico_isp_ssid():
    pins = get_oui_pins(BSSID, ssid="INFINITUM9F3A")
    assert DEFAULT_WPS_PIN in pins


def test_get_oui_pins_matches_totalplay_and_izzi_prefixes():
    assert DEFAULT_WPS_PIN in get_oui_pins(BSSID, ssid="Totalplay-1234")
    assert DEFAULT_WPS_PIN in get_oui_pins(BSSID, ssid="IZZI-5678")


def test_get_oui_pins_matches_huawei_oui():
    huawei_bssid = "00:46:4B:11:22:33"
    pins = get_oui_pins(huawei_bssid, ssid="RandomSSID")
    assert DEFAULT_WPS_PIN in pins


def test_get_oui_pins_includes_pin32_mac_derived_candidate():
    pins = get_oui_pins(BSSID, ssid="RandomSSID")
    expected_pin32 = WPSpin().generate("pin32", BSSID)
    assert expected_pin32 in pins


def test_get_oui_pins_handles_none_ssid():
    pins = get_oui_pins(BSSID, ssid=None)
    assert pins[0] == DEFAULT_WPS_PIN
