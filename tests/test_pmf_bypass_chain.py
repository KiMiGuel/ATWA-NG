"""attacks/eviltwin.py's run_pmf_bypass_chain() (Phase 4.8, v2.4) -- the
attack surface that finally delivers attacks/pmf_bypass.py's malformed-
Message-1/4 primitive: rogue PMF-required twin, wait for a client to
associate, inject the bypass frame, capture the reconnect handshake. All
subprocess/radio calls are mocked; nothing here touches real hardware."""
from __future__ import annotations

import threading

import atwa.attacks.eviltwin as eviltwin_mod
import atwa.attacks.pmf_bypass as pmf_bypass_mod
import atwa.radio as radio_mod
from atwa.attacks.eviltwin import (
    PmfBypassResult,
    _hostapd_conf_wpa2,
    run_pmf_bypass_chain,
)
from atwa.attacks.handshake import HandshakeCapture, HandshakeStatus


def test_hostapd_conf_wpa2_sets_pmf_required_when_asked():
    conf = _hostapd_conf_wpa2("wlan1", "HomeNet", 6, "throwaway123", require_pmf=True)
    assert "ieee80211w=2" in conf


def test_hostapd_conf_wpa2_omits_pmf_by_default():
    conf = _hostapd_conf_wpa2("wlan1", "HomeNet", 6, "throwaway123")
    assert "ieee80211w" not in conf


class _FakeProc:
    def __init__(self, alive=True):
        self.pid = 12345
        self._alive = alive

    def poll(self):
        return None if self._alive else 1


class _FakeTempFile:
    def __init__(self):
        self.name = "/tmp/fake_hostapd.conf"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, data):
        pass


def _patch_common(monkeypatch, *, hostapd_alive=True, rogue_mac="de:ad:be:ef:00:01"):
    monkeypatch.setattr(eviltwin_mod, "_assign_ip", lambda iface: True)
    monkeypatch.setattr(eviltwin_mod, "_flush_ip", lambda iface: None)
    monkeypatch.setattr(eviltwin_mod, "_popen", lambda cmd: _FakeProc(alive=hostapd_alive))
    monkeypatch.setattr(eviltwin_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(eviltwin_mod.os, "killpg", lambda *a, **k: None)
    monkeypatch.setattr(eviltwin_mod.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(eviltwin_mod.tempfile, "NamedTemporaryFile", lambda *a, **kw: _FakeTempFile())
    monkeypatch.setattr(eviltwin_mod.os, "unlink", lambda path: None)
    monkeypatch.setattr(radio_mod, "get_mac", lambda iface: rogue_mac)


def test_pmf_bypass_chain_reports_hostapd_failure_cleanly(monkeypatch, tmp_path):
    _patch_common(monkeypatch, hostapd_alive=False)
    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
    )
    assert isinstance(result, PmfBypassResult)
    assert "hostapd" in result.detail.lower()


def test_pmf_bypass_chain_reports_missing_bssid_cleanly(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(radio_mod, "get_mac", lambda iface: (_ for _ in ()).throw(RuntimeError("no such device")))
    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
    )
    assert "mac address" in result.detail.lower()


def test_pmf_bypass_chain_reports_no_client_associated(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: [])
    stop_event = threading.Event()

    # assoc_timeout=0 makes the wait loop's deadline already-past on entry
    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
        assoc_timeout=0.0, stop_event=stop_event,
    )
    assert result.status is HandshakeStatus.NONE
    assert "no client" in result.detail.lower()


def test_pmf_bypass_chain_stops_immediately_when_already_stopped(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: [])
    stop_event = threading.Event()
    stop_event.set()

    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"), stop_event=stop_event,
    )
    assert "stopped" in result.detail.lower()


def test_pmf_bypass_chain_targets_first_seen_client_and_captures_handshake(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: ["11:22:33:44:55:66"])

    injected = []
    monkeypatch.setattr(
        pmf_bypass_mod, "inject_pmf_bypass",
        lambda iface, bssid, client, key_info=pmf_bypass_mod.KEY_INFO_WPA3_PMF: injected.append((bssid, client, key_info)),
    )

    cap = HandshakeCapture()
    cap.add("de:ad:be:ef:00:01", "11:22:33:44:55:66", 1)
    cap.add("de:ad:be:ef:00:01", "11:22:33:44:55:66", 2)
    cap.add("de:ad:be:ef:00:01", "11:22:33:44:55:66", 3)

    def fake_capture_handshake(iface, bssid, channel=None, timeout=60.0, outfile=None, stop_event=None, progress_fn=None):
        return cap

    monkeypatch.setattr(eviltwin_mod, "_capture_handshake", fake_capture_handshake)

    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
    )

    assert injected == [("de:ad:be:ef:00:01", "11:22:33:44:55:66", pmf_bypass_mod.KEY_INFO_WPA3_PMF)]
    assert result.client_mac == "11:22:33:44:55:66"
    assert result.status is HandshakeStatus.AUTHORIZED
    assert result.outfile == str(tmp_path / "cap.pcap")


def test_pmf_bypass_chain_targets_specific_client_when_given(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"])
    monkeypatch.setattr(pmf_bypass_mod, "inject_pmf_bypass", lambda *a, **kw: None)
    monkeypatch.setattr(eviltwin_mod, "_capture_handshake", lambda *a, **kw: HandshakeCapture())

    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
        client="bb:bb:bb:bb:bb:bb",
    )

    assert result.client_mac == "bb:bb:bb:bb:bb:bb"


def test_pmf_bypass_chain_reports_no_reconnect_without_crashing_on_injection_failure(monkeypatch, tmp_path):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: ["11:22:33:44:55:66"])

    def raising_inject(*a, **kw):
        raise OSError("socket error")

    monkeypatch.setattr(pmf_bypass_mod, "inject_pmf_bypass", raising_inject)
    monkeypatch.setattr(eviltwin_mod, "_capture_handshake", lambda *a, **kw: HandshakeCapture())

    result = run_pmf_bypass_chain(
        "wlan1", "wlan0", "HomeNet", 6, outfile=str(tmp_path / "cap.pcap"),
    )

    assert result.status is HandshakeStatus.NONE
    assert result.client_mac == "11:22:33:44:55:66"
    assert "did not reconnect" in result.detail.lower() or "ignored" in result.detail.lower()
