"""attacks/deauth.py: deauth() must not silently claim success when the
interface isn't actually in monitor mode or the OS-level send fails --
see the function's own docstring for why (real, previously-silent
failure mode)."""
from __future__ import annotations

import atwa.attacks.deauth as deauth_module


def test_deauth_returns_zero_when_iface_not_in_monitor_mode(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "managed")
    sent = []
    monkeypatch.setattr(deauth_module, "sendp", lambda *a, **kw: sent.append(kw))

    result = deauth_module.deauth("wlan0", "aa:bb:cc:dd:ee:ff", count=64)

    assert result == 0
    assert sent == []  # never even tried to send


def test_deauth_returns_count_on_success(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sent = []
    monkeypatch.setattr(deauth_module, "sendp", lambda *a, **kw: sent.append(kw))

    result = deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=32)

    assert result == 32
    assert sent and sent[0]["count"] == 32


def test_deauth_returns_zero_on_os_error(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")

    def raise_oserror(*a, **kw):
        raise OSError("network is down")

    monkeypatch.setattr(deauth_module, "sendp", raise_oserror)

    result = deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=64)

    assert result == 0


def test_deauth_logs_via_progress_fn(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(deauth_module, "sendp", lambda *a, **kw: None)
    messages = []

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=10, progress_fn=messages.append)

    assert any("sent 10 deauth frame" in m for m in messages)


def test_deauth_logs_warning_when_not_monitor_mode(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "managed")
    monkeypatch.setattr(deauth_module, "sendp", lambda *a, **kw: None)
    messages = []

    deauth_module.deauth("wlan0", "aa:bb:cc:dd:ee:ff", progress_fn=messages.append)

    assert any("WARNING" in m and "managed" in m for m in messages)


def test_deauth_sets_channel_when_given(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(deauth_module, "sendp", lambda *a, **kw: None)
    calls = []
    monkeypatch.setattr(deauth_module, "set_channel", lambda iface, ch: calls.append((iface, ch)))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", channel=6)

    assert calls == [("wlan0mon", 6)]


def test_deauth_low_rate_forces_radiotap_rate(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sent = []
    monkeypatch.setattr(deauth_module, "sendp", lambda pkt, **kw: sent.append(pkt))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=1, low_rate=True)

    assert sent[0].getlayer("RadioTap").Rate == 12


def test_deauth_default_leaves_rate_unset(monkeypatch):
    monkeypatch.setattr(deauth_module, "get_mode", lambda iface: "monitor")
    sent = []
    monkeypatch.setattr(deauth_module, "sendp", lambda pkt, **kw: sent.append(pkt))

    deauth_module.deauth("wlan0mon", "aa:bb:cc:dd:ee:ff", count=1)

    assert not sent[0].getlayer("RadioTap").present
