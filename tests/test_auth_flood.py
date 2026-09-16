"""attacks/auth_flood.py: auth_flood() must not silently claim success
when the interface isn't in monitor mode or the socket write fails (same
contract as attacks/deauth.py), and each frame must use a fresh spoofed
source MAC."""
from __future__ import annotations

import threading

import atwa.attacks.auth_flood as auth_flood_module


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


def test_auth_flood_returns_zero_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(auth_flood_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(auth_flood_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(auth_flood_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = auth_flood_module.auth_flood("wlan0", "aa:bb:cc:dd:ee:ff", count=10)

    assert result == 0
    assert sockets == []


def test_auth_flood_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(auth_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(auth_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(auth_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = auth_flood_module.auth_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=15)

    assert result == 15
    assert len(sock.sent) == 15
    assert sock.closed


def test_auth_flood_randomizes_source_mac_per_frame(monkeypatch):
    monkeypatch.setattr(auth_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(auth_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(auth_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    auth_flood_module.auth_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10)

    sources = {pkt.addr2 for pkt in sock.sent}
    assert len(sources) > 1


def test_auth_flood_stops_immediately_on_stop_event(monkeypatch):
    monkeypatch.setattr(auth_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(auth_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(auth_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    stop_event = threading.Event()
    stop_event.set()

    result = auth_flood_module.auth_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10, stop_event=stop_event)

    assert result == 0
    assert sock.sent == []
