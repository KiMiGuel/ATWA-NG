"""Tests for scan_airodump.py — CSV parsing (pure logic, no hardware)
and the AirodumpNotBuilt guard. Fixture CSV text below is a trimmed,
real airodump-ng-01.csv captured live during development (2026-08-25,
wlan1), not synthesized, so field spacing/formatting matches what the
real binary actually emits."""

import subprocess

import pytest

from atwa.scan_airodump import (
    AIRODUMP_NG_BIN,
    AirodumpNotBuilt,
    Network,
    ScanResult,
    _csv_field,
    _format_bssid,
    parse_airodump_csv,
    scan,
)

REAL_AP_SECTION = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
E8:ED:05:08:83:00, 2026-08-25 10:07:12, 2026-08-25 10:07:20,  6, 130, WPA2, CCMP, PSK, -72,       40,        6,   0.  0.  0.  0,  10, ARRIS-8302,
A0:95:7F:0E:F0:D4, 2026-08-25 10:07:12, 2026-08-25 10:07:20,  6, 130, WPA2, CCMP, PSK, -49,       59,        3,   0.  0.  0.  0,  13, INFINITUM2773,
22:87:EC:67:42:B1, 2026-08-25 10:07:12, 2026-08-25 10:07:14,  6,  -1, WPA, ,   ,  -1,        0,        1,   0.  0.  0.  0,   0, ,
BC:47:32:22:D1:29, 2026-08-25 10:07:12, 2026-08-25 10:07:19,  6, 130, OPN, ,   , -72,       34,        0,   0.  0.  0.  0,  19, Club_Totalplay_WiFi, """

REAL_CLIENT_SECTION = """Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
1C:93:C4:36:D6:31, 2026-08-25 10:07:13, 2026-08-25 10:07:19, -56,       19, A0:95:7F:0E:F0:D4, """


# --- _format_bssid / _csv_field ---------------------------------------------


def test_format_bssid_uppercases_and_strips():
    assert _format_bssid("  a0:95:7f:0e:f0:d4 ") == "A0:95:7F:0E:F0:D4"


def test_csv_field_returns_first_nonempty():
    row = {"# Beacons": "", "#Beacons": "42"}
    assert _csv_field(row, "# Beacons", "#Beacons") == "42"


def test_csv_field_all_empty_returns_empty_string():
    assert _csv_field({"a": "", "b": ""}, "a", "b") == ""


# --- parse_airodump_csv: APs -------------------------------------------------


def test_parse_empty_text_returns_empty_result():
    result = parse_airodump_csv("")
    assert result.networks == []
    assert result.clients == []


def test_parse_whitespace_only_returns_empty_result():
    result = parse_airodump_csv("   \n\n  \n")
    assert result.networks == []


def test_parse_real_ap_section_fields():
    result = parse_airodump_csv(REAL_AP_SECTION)
    assert len(result.networks) == 4
    infinitum = next(n for n in result.networks if n.essid == "INFINITUM2773")
    assert infinitum.bssid == "A0:95:7F:0E:F0:D4"
    assert infinitum.channel == "6"
    assert infinitum.privacy == "WPA2"
    assert infinitum.cipher == "CCMP"
    assert infinitum.auth == "PSK"
    assert infinitum.power == "-49"
    assert infinitum.beacons == "59"
    assert infinitum.iv == "3"


def test_parse_hidden_ssid_becomes_hidden_marker():
    result = parse_airodump_csv(REAL_AP_SECTION)
    # Exactly one row in the fixture has a genuinely blank ESSID field
    # (22:87:EC:67:42:B1); the OPN row has a real ESSID, not blank.
    hidden = [n for n in result.networks if n.essid == "[Hidden]"]
    assert len(hidden) == 1
    assert hidden[0].bssid == "22:87:EC:67:42:B1"


def test_parse_open_network_privacy():
    result = parse_airodump_csv(REAL_AP_SECTION)
    open_net = next(n for n in result.networks if n.bssid == "BC:47:32:22:D1:29")
    assert open_net.privacy == "OPN"
    assert open_net.cipher == ""


def test_parse_length_prefixed_essid_becomes_hidden():
    csv_text = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
        "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, t, t,  6, 130, WPA2, CCMP, PSK, -50, 10, 0, 0.0.0.0, 8, <length:  8>, "
    )
    result = parse_airodump_csv(csv_text)
    assert result.networks[0].essid == "[Hidden]"


# --- parse_airodump_csv: clients --------------------------------------------


def test_parse_clients_section():
    text = REAL_AP_SECTION + "\n\n" + REAL_CLIENT_SECTION
    result = parse_airodump_csv(text)
    assert len(result.clients) == 1
    client = result.clients[0]
    assert client.station == "1C:93:C4:36:D6:31"
    assert client.bssid == "A0:95:7F:0E:F0:D4"
    assert client.power == "-56"
    assert client.packets == "19"


def test_parse_no_client_section_present():
    result = parse_airodump_csv(REAL_AP_SECTION)
    assert result.clients == []


def test_parse_beacon_field_name_variants():
    """Real airodump-ng CSVs use "# beacons" (lowercase b in the header
    seen live) but older/other versions/tools may emit different
    casing/spacing — _csv_field's fallback list covers this."""
    csv_text = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
        "Cipher, Authentication, Power, #Beacons, #IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, t, t,  6, 130, WPA2, CCMP, PSK, -50, 99, 5, 0.0.0.0, 8, Test, "
    )
    result = parse_airodump_csv(csv_text)
    assert result.networks[0].beacons == "99"
    assert result.networks[0].iv == "5"


# --- scan(): AirodumpNotBuilt guard ------------------------------------------


def test_scan_raises_when_binary_not_built(monkeypatch, tmp_path):
    fake_bin = tmp_path / "airodump-ng"  # deliberately not created
    monkeypatch.setattr("atwa.scan_airodump.AIRODUMP_NG_BIN", fake_bin)
    with pytest.raises(AirodumpNotBuilt):
        scan("wlan0", duration=1.0)


def test_scan_error_message_includes_build_instructions(monkeypatch, tmp_path):
    fake_bin = tmp_path / "airodump-ng"
    monkeypatch.setattr("atwa.scan_airodump.AIRODUMP_NG_BIN", fake_bin)
    with pytest.raises(AirodumpNotBuilt, match="autoreconf"):
        scan("wlan0", duration=1.0)


def test_scan_closes_stdin_on_the_subprocess(monkeypatch, tmp_path):
    """Regression test for the stdin-inheritance hang bug found during
    code review (2026-08-25) — Popen must be called with
    stdin=subprocess.DEVNULL, or a real invocation can block forever."""
    fake_bin = tmp_path / "airodump-ng"
    fake_bin.write_text("")
    monkeypatch.setattr("atwa.scan_airodump.AIRODUMP_NG_BIN", fake_bin)

    captured_kwargs = {}

    class FakeProc:
        def send_signal(self, sig):
            pass

        def wait(self, timeout=None):
            pass

    def fake_popen(cmd, **kwargs):
        captured_kwargs.update(kwargs)
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr("atwa.scan_airodump.time.sleep", lambda _s: None)

    scan("wlan0", duration=0.01)
    assert captured_kwargs.get("stdin") == subprocess.DEVNULL
