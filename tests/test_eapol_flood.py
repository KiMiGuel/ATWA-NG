"""attacks/eapol_flood.py: eapol_flood() must not silently claim success
when the interface isn't in monitor mode or the socket write fails (same
contract as attacks/deauth.py), and randomize_client must actually vary
the spoofed source MAC per frame."""
from __future__ import annotations

import threading

import atwa.attacks.eapol_flood as eapol_flood_module


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


def test_eapol_flood_returns_zero_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(eapol_flood_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(eapol_flood_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(eapol_flood_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = eapol_flood_module.eapol_flood("wlan0", "aa:bb:cc:dd:ee:ff", count=10)

    assert result == 0
    assert sockets == []


def test_eapol_flood_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(eapol_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(eapol_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(eapol_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = eapol_flood_module.eapol_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=20)

    assert result == 20
    assert len(sock.sent) == 20
    assert sock.closed


def test_eapol_flood_randomizes_source_mac_per_frame_by_default(monkeypatch):
    monkeypatch.setattr(eapol_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(eapol_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(eapol_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    eapol_flood_module.eapol_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10)

    sources = {pkt.addr2 for pkt in sock.sent}
    assert len(sources) > 1  # not all the same spoofed client


def test_eapol_flood_uses_fixed_client_when_randomize_disabled(monkeypatch):
    monkeypatch.setattr(eapol_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(eapol_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(eapol_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    eapol_flood_module.eapol_flood(
        "wlan0mon", "aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66", count=5, randomize_client=False,
    )

    sources = {pkt.addr2 for pkt in sock.sent}
    assert sources == {"11:22:33:44:55:66"}


def test_eapol_flood_requires_client_when_randomize_disabled():
    import pytest

    with pytest.raises(ValueError):
        eapol_flood_module.eapol_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", randomize_client=False)


def test_eapol_flood_stops_immediately_on_stop_event(monkeypatch):
    monkeypatch.setattr(eapol_flood_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(eapol_flood_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(eapol_flood_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    stop_event = threading.Event()
    stop_event.set()

    result = eapol_flood_module.eapol_flood("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10, stop_event=stop_event)

    assert result == 0
    assert sock.sent == []
