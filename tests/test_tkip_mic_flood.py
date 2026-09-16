"""attacks/tkip_mic_flood.py: tkip_mic_flood() must not silently claim
success when the interface isn't in monitor mode or the socket write
fails (same contract as attacks/deauth.py), and must default to sending
exactly 2 frames (the countermeasure threshold -- see module docstring)."""
from __future__ import annotations

import threading

import atwa.attacks.tkip_mic_flood as tkip_module


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


def test_tkip_mic_flood_returns_zero_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(tkip_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(tkip_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(tkip_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = tkip_module.tkip_mic_flood("wlan0", "aa:bb:cc:dd:ee:ff")

    assert result == 0
    assert sockets == []


def test_tkip_mic_flood_defaults_to_two_frames(monkeypatch):
    monkeypatch.setattr(tkip_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(tkip_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(tkip_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = tkip_module.tkip_mic_flood("wlan0mon", "aa:bb:cc:dd:ee:ff")

    assert result == 2
    assert len(sock.sent) == 2
    assert sock.closed


def test_tkip_mic_flood_frames_have_protected_bit_set(monkeypatch):
    monkeypatch.setattr(tkip_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(tkip_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(tkip_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    tkip_module.tkip_mic_flood("wlan0mon", "aa:bb:cc:dd:ee:ff")

    for pkt in sock.sent:
        assert "protected" in pkt.FCfield


def test_tkip_mic_flood_returns_zero_on_socket_open_failure(monkeypatch):
    monkeypatch.setattr(tkip_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(tkip_module.conf, "L2socket", lambda **kw: _FakeSocket(open_fails=True))

    result = tkip_module.tkip_mic_flood("wlan0mon", "aa:bb:cc:dd:ee:ff")

    assert result == 0


def test_tkip_mic_flood_stops_immediately_on_stop_event(monkeypatch):
    monkeypatch.setattr(tkip_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(tkip_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(tkip_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    stop_event = threading.Event()
    stop_event.set()

    result = tkip_module.tkip_mic_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", stop_event=stop_event)

    assert result == 0
    assert sock.sent == []
