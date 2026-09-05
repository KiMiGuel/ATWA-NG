"""attacks/deauth.py: deauth() must not silently claim success when the
interface isn't actually in monitor mode or the socket write fails --
see the function's own docstring for why (real, previously-silent
failure mode). Also covers the per-frame send/log loop (one
socket.send() + one log line per deauth frame, not a single batched
sendp(count=...) with one summary line -- the user wants to see every
frame as it goes out)."""
from __future__ import annotations

import atwa.attacks.deauth as deauth_module


class _FakeSocket:
    """Stand-in for conf.L2socket(iface=...): records every .send() call."""

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


def test_deauth_returns_zero_when_iface_not_in_monitor_mode(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(deauth_module, "ensure_monitor_mode", lambda iface: None)
    sockets = []
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sockets.append(_FakeSocket()) or sockets[-1])

    result = deauth_module.deauth("wlan0", "aa:bb:cc:dd:ee:ff", count=64)

    assert result == 0
    assert sockets == []  # never even tried to open a socket


def test_deauth_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=32)

    assert result == 32
    assert len(sock.sent) == 32
    assert sock.closed


def test_deauth_returns_zero_on_socket_open_failure(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: _FakeSocket(open_fails=True))

    result = deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=64)

    assert result == 0


def test_deauth_returns_partial_count_on_send_failure(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket(fail_after=5)
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    result = deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=64)

    assert result == 5
    assert sock.closed


def test_deauth_logs_every_frame_via_progress_fn(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: _FakeSocket())
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    messages = []

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10, progress_fn=messages.append)

    frame_lines = [m for m in messages if "deauth frame" in m and "sent" in m]
    assert len(frame_lines) == 10
    assert "deauth frame 1/10 sent" in frame_lines[0]
    assert "deauth frame 10/10 sent" in frame_lines[-1]


def test_deauth_logs_warning_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(deauth_module, "ensure_monitor_mode", lambda iface: None)
    messages = []

    deauth_module.deauth("wlan0", "aa:bb:cc:dd:ee:ff", progress_fn=messages.append)

    assert any("WARNING" in m and "managed" in m for m in messages)


def test_deauth_self_heals_monitor_mode_drift(monkeypatch):
    """If the interface has drifted out of monitor mode (e.g. NetworkManager
    reasserting control mid-session), deauth() should heal it and proceed
    instead of just bailing with a warning like it used to."""
    mode_calls = []

    def fake_get_mode(iface):
        mode_calls.append(iface)
        return "managed" if len(mode_calls) == 1 else "monitor"

    healed = []
    monkeypatch.setattr(deauth_module, "get_mode", fake_get_mode)
    monkeypatch.setattr(deauth_module, "ensure_monitor_mode", lambda iface: healed.append(iface))
    sock = _FakeSocket()
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    messages = []

    result = deauth_module.deauth("wlan0", "aa:bb:cc:dd:ee:ff", count=4, progress_fn=messages.append)

    assert result == 4
    assert healed == ["wlan0"]
    assert any("restored" in m for m in messages)
    assert not any("WARNING" in m for m in messages)


def test_deauth_sets_channel_when_given(monkeypatch):
    import atwa.radio as radio_module

    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: _FakeSocket())
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))
    radio_module.clear_channel_cache()
    calls = []
    monkeypatch.setattr(radio_module, "set_channel", lambda iface, ch: calls.append((iface, ch)))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", channel=6)

    assert calls == [("wlan0mon", 6)]


def test_deauth_low_rate_forces_radiotap_rate(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=1, low_rate=True)

    assert sock.sent[0].getlayer("RadioTap").Rate == 12


def test_deauth_default_leaves_rate_unset(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sock = _FakeSocket()
    monkeypatch.setattr(deauth_module.conf, "L2socket", lambda **kw: sock)
    monkeypatch.setattr(deauth_module, "time", type("T", (), {"sleep": staticmethod(lambda s: None)}))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=1)

    assert not sock.sent[0].getlayer("RadioTap").present
