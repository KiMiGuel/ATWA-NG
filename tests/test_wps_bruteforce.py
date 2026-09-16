"""attacks/wps.py: wps_pin_bruteforce()'s known-default OUI-PIN
pre-attempts (Phase 4.6, v2.4) -- tried after null-PIN, before the real
0000-9999/000-999 split-half sweep. Dependency-injected the same way
null_pin_fn/attempt_fn already are."""
from __future__ import annotations

import threading

from atwa.attacks.wps import AttemptOutcome, AttemptResult, wps_pin_bruteforce

BSSID = "aa:bb:cc:dd:ee:ff"
SSID = "TestNet"


def _no_null_pin(*a, **kw):
    return AttemptResult(outcome=AttemptOutcome.TIMEOUT)


def test_bruteforce_succeeds_via_oui_pin_without_reaching_the_full_sweep():
    sweep_calls = []

    def fake_oui_pins(bssid, ssid):
        return ["12345670", "11111111"]

    def fake_attempt(iface, bssid, pin8, ssid, channel=None, stop_event=None):
        if pin8 == "12345670":
            return AttemptResult(outcome=AttemptOutcome.SUCCESS, ssid=ssid, network_key="hunter2")
        sweep_calls.append(pin8)
        return AttemptResult(outcome=AttemptOutcome.FIRST_HALF_WRONG)

    result = wps_pin_bruteforce(
        "wlan0mon", BSSID, SSID,
        attempt_fn=fake_attempt, try_null_pin=False,
        oui_pins_fn=fake_oui_pins,
    )

    assert result.success is True
    assert result.pin == "12345670"
    assert result.network_key == "hunter2"
    assert result.attempts == 1  # only the winning OUI-PIN attempt, no full sweep at all


def test_bruteforce_falls_through_to_full_sweep_when_oui_pins_all_wrong():
    def fake_oui_pins(bssid, ssid):
        return ["12345670", "11111111"]

    attempted_pins = []

    def fake_attempt(iface, bssid, pin8, ssid, channel=None, stop_event=None):
        attempted_pins.append(pin8)
        if pin8 in ("12345670", "11111111"):
            return AttemptResult(outcome=AttemptOutcome.FIRST_HALF_WRONG)
        # Stop the test quickly once past the 2 OUI-PIN attempts -- pretend
        # the very next real sweep guess (0000000+checksum) succeeds.
        return AttemptResult(outcome=AttemptOutcome.SUCCESS)

    result = wps_pin_bruteforce(
        "wlan0mon", BSSID, SSID,
        attempt_fn=fake_attempt, try_null_pin=False,
        oui_pins_fn=fake_oui_pins,
    )

    assert attempted_pins[:2] == ["12345670", "11111111"]
    assert result.success is True
    assert result.attempts == 3  # 2 OUI-PIN attempts + 1 real sweep attempt


def test_bruteforce_skips_oui_pins_when_disabled():
    calls = []

    def fake_oui_pins(bssid, ssid):
        calls.append(True)
        return ["12345670"]

    def fake_attempt(iface, bssid, pin8, ssid, channel=None, stop_event=None):
        return AttemptResult(outcome=AttemptOutcome.SUCCESS)

    wps_pin_bruteforce(
        "wlan0mon", BSSID, SSID,
        attempt_fn=fake_attempt, try_null_pin=False,
        try_oui_pins=False, oui_pins_fn=fake_oui_pins,
    )

    assert calls == []


def test_bruteforce_oui_pins_abort_on_ap_setup_locked():
    def fake_oui_pins(bssid, ssid):
        return ["12345670"]

    def fake_attempt(iface, bssid, pin8, ssid, channel=None, stop_event=None):
        return AttemptResult(outcome=AttemptOutcome.AP_SETUP_LOCKED)

    result = wps_pin_bruteforce(
        "wlan0mon", BSSID, SSID,
        attempt_fn=fake_attempt, try_null_pin=False,
        oui_pins_fn=fake_oui_pins,
    )

    assert result.success is False
    assert result.ap_setup_locked is True
    assert result.attempts == 1


def test_bruteforce_oui_pins_stop_immediately_on_stop_event():
    stop_event = threading.Event()
    stop_event.set()
    calls = []

    def fake_oui_pins(bssid, ssid):
        calls.append(True)
        return ["12345670"]

    def fake_attempt(*a, **kw):
        raise AssertionError("must not attempt any PIN once stop_event is set")

    result = wps_pin_bruteforce(
        "wlan0mon", BSSID, SSID,
        attempt_fn=fake_attempt, try_null_pin=False,
        oui_pins_fn=fake_oui_pins, stop_event=stop_event,
    )

    assert result.attempts == 0
    assert result.success is False
