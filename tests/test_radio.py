"""radio.py: channel helpers and ensure_channel() cache behavior."""
from __future__ import annotations

import pytest

import atwa.radio as radio


@pytest.fixture(autouse=True)
def _clear_channel_cache():
    """Each test starts with a clean ensure_channel() cache."""
    radio.clear_channel_cache()
    yield


def test_ensure_channel_no_op_when_none():
    calls = []
    radio.set_channel = lambda iface, ch: calls.append((iface, ch))  # type: ignore[method-assign]

    assert radio.ensure_channel("wlan0", None) is False
    assert calls == []


def test_ensure_channel_calls_set_channel_on_change(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "set_channel", lambda iface, ch: calls.append((iface, ch)))

    assert radio.ensure_channel("wlan0", 6) is True
    assert calls == [("wlan0", 6)]


def test_ensure_channel_skips_repeat_same_channel(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "set_channel", lambda iface, ch: calls.append((iface, ch)))

    assert radio.ensure_channel("wlan0", 6) is True
    assert radio.ensure_channel("wlan0", 6) is False
    assert calls == [("wlan0", 6)]


def test_ensure_channel_tracks_interfaces_independently(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "set_channel", lambda iface, ch: calls.append((iface, ch)))

    assert radio.ensure_channel("wlan0", 6) is True
    assert radio.ensure_channel("wlan1", 6) is True  # same channel, different iface
    assert radio.ensure_channel("wlan0", 11) is True
    assert calls == [("wlan0", 6), ("wlan1", 6), ("wlan0", 11)]


def test_ensure_channel_propagates_exception_without_caching(monkeypatch):
    def boom(iface, ch):
        raise radio.RadioError("fail")

    monkeypatch.setattr(radio, "set_channel", boom)

    with pytest.raises(radio.RadioError):
        radio.ensure_channel("wlan0", 6)
    # Cache should not record the failed channel.
    assert radio._last_channel.get("wlan0") is None


def test_clear_channel_cache_single_iface():
    radio._last_channel["wlan0"] = 6
    radio._last_channel["wlan1"] = 11
    radio.clear_channel_cache("wlan0")
    assert "wlan0" not in radio._last_channel
    assert radio._last_channel.get("wlan1") == 11


def test_clear_channel_cache_all():
    radio._last_channel["wlan0"] = 6
    radio.clear_channel_cache()
    assert radio._last_channel == {}
