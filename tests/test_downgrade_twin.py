"""attacks/eviltwin.py's run_downgrade_twin() -- the WPA3-transition
rogue WPA2-only twin (secure.py's downgrade_twin recommendation). All
subprocess/radio calls are mocked; nothing here touches real hardware."""

from __future__ import annotations

import threading

import atwa.attacks.eviltwin as eviltwin_mod
import atwa.radio as radio_mod
from atwa.attacks.eviltwin import (
    DowngradeTwinResult,
    _hostapd_conf_wpa2,
    _random_passphrase,
    run_downgrade_twin,
)
from atwa.attacks.handshake import HandshakeCapture, HandshakeStatus


def test_hostapd_conf_wpa2_contains_expected_fields():
    conf = _hostapd_conf_wpa2("wlan1", "HomeNet", 6, "throwaway123")
    assert "interface=wlan1" in conf
    assert "ssid=HomeNet" in conf
    assert "channel=6" in conf
    assert "wpa=2" in conf
    assert "wpa_passphrase=throwaway123" in conf
    assert "wpa_key_mgmt=WPA-PSK" in conf


def test_hostapd_conf_wpa2_clamps_channel_above_13():
    conf = _hostapd_conf_wpa2("wlan1", "HomeNet", 100, "throwaway123")
    assert "channel=6" in conf


def test_random_passphrase_within_hostapd_valid_range():
    for _ in range(5):
        pw = _random_passphrase()
        assert 8 <= len(pw) <= 63


def test_random_passphrase_not_reused():
    assert _random_passphrase() != _random_passphrase()


class _FakeProc:
    def __init__(self, alive=True):
        self.pid = 12345
        self._alive = alive

    def poll(self):
        return None if self._alive else 1


def _patch_common(monkeypatch, *, hostapd_alive=True, rogue_mac="de:ad:be:ef:00:01"):
    monkeypatch.setattr(eviltwin_mod, "_assign_ip", lambda iface: True)
    monkeypatch.setattr(eviltwin_mod, "_flush_ip", lambda iface: None)
    monkeypatch.setattr(eviltwin_mod, "_popen", lambda cmd: _FakeProc(alive=hostapd_alive))
    monkeypatch.setattr(eviltwin_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(eviltwin_mod.os, "killpg", lambda *a, **k: None)
    monkeypatch.setattr(eviltwin_mod.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(eviltwin_mod.tempfile, "NamedTemporaryFile", _fake_tempfile)
    monkeypatch.setattr(eviltwin_mod.os, "unlink", lambda path: None)
    monkeypatch.setattr(radio_mod, "get_mac", lambda iface: rogue_mac)


class _FakeTempFile:
    def __init__(self):
        self.name = "/tmp/fake_hostapd.conf"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, data):
        pass


def _fake_tempfile(*args, **kwargs):
    return _FakeTempFile()


def test_downgrade_twin_reports_hostapd_failure_cleanly(monkeypatch, tmp_path):
    _patch_common(monkeypatch, hostapd_alive=False)
    result = run_downgrade_twin(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeNet", 6,
        outfile=str(tmp_path / "cap.pcap"),
    )
    assert isinstance(result, DowngradeTwinResult)
    assert result.status is HandshakeStatus.NONE
    assert "hostapd" in result.detail.lower()


def test_downgrade_twin_reports_missing_bssid_cleanly(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(radio_mod, "get_mac", lambda iface: (_ for _ in ()).throw(RuntimeError("no such device")))
    result = run_downgrade_twin(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeNet", 6,
        outfile=str(tmp_path / "cap.pcap"),
    )
    assert result.status is HandshakeStatus.NONE
    assert "mac address" in result.detail.lower()


def test_downgrade_twin_captures_challenge_handshake(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_deauth", lambda *a, **k: 64)

    cap = HandshakeCapture()
    cap.add("de:ad:be:ef:00:01", "11:22:33:44:55:66", 1)
    cap.add("de:ad:be:ef:00:01", "11:22:33:44:55:66", 2)

    def fake_capture_handshake(iface, bssid, channel=None, timeout=60.0, outfile=None, stop_event=None, progress_fn=None):
        return cap

    monkeypatch.setattr(eviltwin_mod, "_capture_handshake", fake_capture_handshake)

    result = run_downgrade_twin(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeNet", 6,
        outfile=str(tmp_path / "cap.pcap"), timeout=2.0,
    )
    assert result.status is HandshakeStatus.CHALLENGE
    assert result.outfile == str(tmp_path / "cap.pcap")


def test_downgrade_twin_reports_no_client_attempted(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_deauth", lambda *a, **k: 64)
    monkeypatch.setattr(eviltwin_mod, "_capture_handshake", lambda *a, **k: HandshakeCapture())

    stop_event = threading.Event()
    stop_event.set()  # already stopped -- loop exits immediately with nothing captured
    result = run_downgrade_twin(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeNet", 6,
        outfile=str(tmp_path / "cap.pcap"), stop_event=stop_event,
    )
    assert result.status is HandshakeStatus.NONE
    assert "no client" in result.detail.lower()
