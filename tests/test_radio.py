"""radio.py: channel helpers and ensure_channel() cache behavior."""
from __future__ import annotations

import pytest

import atwa.radio as radio


@pytest.fixture(autouse=True)
def _clear_channel_cache():
    """Each test starts with a clean ensure_channel() cache."""
    radio.clear_channel_cache()
    radio.clear_driver_cache()
    yield


def test_get_driver_caches_across_calls(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return "driver: mt76x0u\n"

    monkeypatch.setattr(radio, "_run", fake_run)
    assert radio.get_driver("wlan1") == "mt76x0u"
    assert radio.get_driver("wlan1") == "mt76x0u"
    assert len(calls) == 1


def test_get_driver_caches_undetermined_result(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        raise radio.RadioError("no such device")

    monkeypatch.setattr(radio, "_run", fake_run)
    assert radio.get_driver("wlan9") is None
    assert radio.get_driver("wlan9") is None
    assert len(calls) == 1


def test_get_driver_tracks_interfaces_independently(monkeypatch):
    monkeypatch.setattr(radio, "_run", lambda cmd: f"driver: driver-for-{cmd[-1]}\n")
    assert radio.get_driver("wlan0") == "driver-for-wlan0"
    assert radio.get_driver("wlan1") == "driver-for-wlan1"


def test_clear_driver_cache_single_iface(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "_run", lambda cmd: calls.append(cmd) or "driver: mt76x0u\n")
    radio.get_driver("wlan0")
    radio.get_driver("wlan1")
    radio.clear_driver_cache("wlan0")
    radio.get_driver("wlan0")
    radio.get_driver("wlan1")
    assert len(calls) == 3  # wlan0, wlan1, wlan0-again (wlan1 stayed cached)


def test_clear_driver_cache_all(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "_run", lambda cmd: calls.append(cmd) or "driver: mt76x0u\n")
    radio.get_driver("wlan0")
    radio.clear_driver_cache()
    radio.get_driver("wlan0")
    assert len(calls) == 2


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


def test_disable_power_save_runs_iw_command(monkeypatch):
    calls = []
    monkeypatch.setattr(radio, "_run", lambda cmd: calls.append(cmd) or "")
    assert radio.disable_power_save("wlan1") is True
    assert calls == [["iw", "dev", "wlan1", "set", "power_save", "off"]]


def test_disable_power_save_non_fatal_when_unsupported(monkeypatch):
    def boom(cmd):
        raise radio.RadioError("power_save not supported by this driver")

    monkeypatch.setattr(radio, "_run", boom)
    assert radio.disable_power_save("wlan1") is False


def test_get_channel_parses_iw_output(monkeypatch):
    monkeypatch.setattr(
        radio, "_run",
        lambda cmd: "Interface wlan0\n\ttype monitor\n\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz\n",
    )
    assert radio.get_channel("wlan0") == 6


def test_get_channel_returns_none_when_not_tuned(monkeypatch):
    monkeypatch.setattr(radio, "_run", lambda cmd: "Interface wlan0\n\ttype managed\n")
    assert radio.get_channel("wlan0") is None


def test_ensure_monitor_mode_restores_and_clears_channel_cache(monkeypatch):
    radio._last_channel["wlan0"] = 6
    calls = []
    monkeypatch.setattr(radio, "check_kill_interfering_processes", lambda: calls.append("kill") or [])
    monkeypatch.setattr(radio, "set_monitor_mode", lambda iface, **kw: calls.append(("set_monitor_mode", iface)) or (iface, None))

    radio.ensure_monitor_mode("wlan0")

    assert calls == ["kill", ("set_monitor_mode", "wlan0")]
    assert "wlan0" not in radio._last_channel


def test_check_and_heal_returns_no_actions_when_healthy(monkeypatch):
    monkeypatch.setattr(radio, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(radio, "get_channel", lambda iface: 6)
    set_channel_calls = []
    monkeypatch.setattr(radio, "set_channel", lambda iface, ch: set_channel_calls.append((iface, ch)))

    actions = radio.check_and_heal("wlan0", expected_channel=6)

    assert actions == []
    assert set_channel_calls == []


def test_check_and_heal_restores_dropped_monitor_mode(monkeypatch):
    monkeypatch.setattr(radio, "get_mode", lambda iface: "managed")
    healed = []
    monkeypatch.setattr(radio, "ensure_monitor_mode", lambda iface: healed.append(iface))

    actions = radio.check_and_heal("wlan0")

    assert healed == ["wlan0"]
    assert actions == ["wlan0 had dropped out of monitor mode -- restored"]


def test_check_and_heal_corrects_channel_drift(monkeypatch):
    monkeypatch.setattr(radio, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(radio, "get_channel", lambda iface: 1)
    set_channel_calls = []
    monkeypatch.setattr(radio, "set_channel", lambda iface, ch: set_channel_calls.append((iface, ch)))

    actions = radio.check_and_heal("wlan0", expected_channel=6)

    assert set_channel_calls == [("wlan0", 6)]
    assert radio._last_channel["wlan0"] == 6
    assert actions == ["wlan0 channel drifted (was 1, expected 6) -- corrected"]


def test_check_and_heal_ignores_channel_when_not_expected(monkeypatch):
    monkeypatch.setattr(radio, "get_mode", lambda iface: "monitor")
    get_channel_calls = []
    monkeypatch.setattr(radio, "get_channel", lambda iface: get_channel_calls.append(iface) or 1)

    actions = radio.check_and_heal("wlan0")

    assert actions == []
    assert get_channel_calls == []  # never checked -- caller didn't ask
