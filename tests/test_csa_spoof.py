"""attacks/csa_spoof.py: send_csa() must not silently claim success when
the interface isn't actually in monitor mode or the socket write fails --
same contract as attacks/deauth.py (see test_deauth.py)."""
from __future__ import annotations

import atwa.attacks.csa_spoof as csa_module


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


def test_send_csa_returns_zero_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(csa_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(csa_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(csa_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = csa_module.send_csa("wlan0", "aa:bb:cc:dd:ee:ff", new_channel=6, count=10)

    assert result == 0
    assert sockets == []


def test_send_csa_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(csa_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(csa_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(csa_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = csa_module.send_csa("wlan0mon", "aa:bb:cc:dd:ee:ff", new_channel=11, count=5)

    assert result == 5
    assert len(sock.sent) == 5
    assert sock.closed


def test_send_csa_returns_zero_on_socket_open_failure(monkeypatch):
    monkeypatch.setattr(csa_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(csa_module.conf, "L2socket", lambda **kw: _FakeSocket(open_fails=True))

    result = csa_module.send_csa("wlan0mon", "aa:bb:cc:dd:ee:ff", new_channel=6, count=10)

    assert result == 0


def test_send_csa_stops_immediately_on_stop_event(monkeypatch):
    import threading

    monkeypatch.setattr(csa_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(csa_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(csa_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    stop_event = threading.Event()
    stop_event.set()

    result = csa_module.send_csa("wlan0mon", "aa:bb:cc:dd:ee:ff", new_channel=6, count=10, stop_event=stop_event)

    assert result == 0
    assert sock.sent == []
