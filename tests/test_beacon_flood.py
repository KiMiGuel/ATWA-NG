"""attacks/beacon_flood.py: beacon_flood() must not silently claim success
when the interface isn't in monitor mode or the socket write fails (same
contract as attacks/deauth.py), must vary the fake BSSID per frame, and
must cycle through an explicit ssids list when given one."""
from __future__ import annotations

import threading

import atwa.attacks.beacon_flood as beacon_flood_module


class _FakeSocket:
    def __init__(self, fail_after: int | None = None, open_fails: bool = False):
        if open_fails:
            raise OSError("network is down")
        self.sent: list = []
        self.closed = False
        self._fail_after = fail_after

    def send(self, pkt):
        if self._fail_after is not None and len(self.sent) >= self._fail_after:
            raise OSError("network is down")
        self.sent.append(pkt)

    def close(self):
        self.closed = True


def test_beacon_flood_returns_zero_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(beacon_flood_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(beacon_flood_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(beacon_flood_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = beacon_flood_module.beacon_flood("wlan0", count=10)

    assert result == 0
    assert sockets == []


def test_beacon_flood_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(beacon_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(beacon_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(beacon_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = beacon_flood_module.beacon_flood("wlan0mon", count=25)

    assert result == 25
    assert len(sock.sent) == 25
    assert sock.closed


def test_beacon_flood_uses_random_bssid_per_frame(monkeypatch):
    monkeypatch.setattr(beacon_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(beacon_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(beacon_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    beacon_flood_module.beacon_flood("wlan0mon", count=10)

    bssids = {pkt.addr2 for pkt in sock.sent}
    assert len(bssids) > 1


def test_beacon_flood_cycles_through_explicit_ssid_list(monkeypatch):
    monkeypatch.setattr(beacon_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(beacon_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(beacon_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    from scapy.layers.dot11 import Dot11Elt

    beacon_flood_module.beacon_flood("wlan0mon", count=4, ssids=["Free_WiFi", "Guest"])

    ssids_sent = []
    for pkt in sock.sent:
        elt = pkt.getlayer(Dot11Elt)
        ssids_sent.append(elt.info.decode())
    assert ssids_sent == ["Free_WiFi", "Guest", "Free_WiFi", "Guest"]


def test_beacon_flood_stops_immediately_on_stop_event(monkeypatch):
    monkeypatch.setattr(beacon_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(beacon_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(beacon_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    stop_event = threading.Event()
    stop_event.set()

    result = beacon_flood_module.beacon_flood("wlan0mon", count=10, stop_event=stop_event)

    assert result == 0
    assert sock.sent == []
