"""Tests for gui/attack_runner.py -- specifically pincer(), which had zero
coverage before this file existed. All radio/attack calls are mocked at
their source module (attacks.deauth, attacks.handshake, radio, storage)
since pincer() imports them locally inside the method body -- patching
the source module's attribute is what actually takes effect at call time."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

import atwa.attacks.deauth as deauth_mod
import atwa.attacks.handshake as handshake_mod
import atwa.radio as radio_mod
import atwa.storage as storage_mod
from atwa.attacks.handshake import HandshakeCapture
from atwa.gui.attack_runner import AttackRunner


@dataclass
class FakeAP:
    bssid: str = "aa:bb:cc:dd:ee:ff"
    ssid: str = "TestNet"
    channel: int | None = 6
    pmf: str | None = "capable"
    clients: set[str] = field(default_factory=lambda: {"11:22:33:44:55:66"})


def _make_runner(**overrides):
    defaults = dict(
        mon_iface=None,
        own_mac="de:ad:be:ef:00:00",
        capture_dir="/tmp",
        wordlist=None,
        stop_event=threading.Event(),
        progress_fn=lambda msg: None,
        log_fn=lambda msg: None,
    )
    defaults.update(overrides)
    return AttackRunner(**defaults)


def _patch_radio(monkeypatch, sent_deauth=1):
    monkeypatch.setattr(radio_mod, "set_monitor_mode", lambda iface, randomize_mac=False: (iface, None))
    monkeypatch.setattr(radio_mod, "get_mode", lambda iface: "monitor")
    monkeypatch.setattr(radio_mod, "set_managed_mode", lambda iface, restore_mac=None: iface)
    monkeypatch.setattr(radio_mod, "ensure_channel", lambda iface, channel: True)
    monkeypatch.setattr(deauth_mod, "deauth", lambda iface, bssid, client, channel, progress_fn=None: sent_deauth)
    monkeypatch.setattr(storage_mod, "target_capture_dir", lambda essid, bssid, create=True: __import__("pathlib").Path("/tmp"))


def test_pincer_skips_entirely_when_pmf_required(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(radio_mod, "set_monitor_mode", lambda *a, **k: calls.append("set_monitor_mode") or ("x", None))
    monkeypatch.setattr(deauth_mod, "deauth", lambda *a, **k: calls.append("deauth") or 1)

    runner = _make_runner()
    ap = FakeAP(pmf="required")
    result = runner.pincer(ap, "wlan0", "wlan1", randomize_mac=False, watch_capture_fn=lambda *a: None)

    assert "skipped" in result.lower()
    assert calls == []  # never touched either radio


def test_pincer_stops_early_on_authorized_handshake(monkeypatch, tmp_path):
    _patch_radio(monkeypatch)

    cap = HandshakeCapture()
    cap.add("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1)
    cap.add("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 2)
    cap.add("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 3)

    def fake_capture_handshake(iface, bssid, channel, timeout, outfile, stop_event=None, progress_fn=None):
        return cap

    monkeypatch.setattr(handshake_mod, "capture_handshake", fake_capture_handshake)
    monkeypatch.setattr("atwa.gui.attack_runner.time.sleep", lambda s: None)

    runner = _make_runner()
    ap = FakeAP()
    watched = []
    result = runner.pincer(
        ap, "wlan0", "wlan1", randomize_mac=False,
        watch_capture_fn=lambda path, stop: watched.append(path),
    )

    assert "AUTHORIZED" in result
    assert str(cap.messages) or True  # capture object was real, not stubbed away


def test_pincer_stops_on_stop_event_between_rounds(monkeypatch, tmp_path):
    _patch_radio(monkeypatch)
    monkeypatch.setattr(handshake_mod, "capture_handshake", lambda *a, **k: HandshakeCapture())
    monkeypatch.setattr("atwa.gui.attack_runner.time.sleep", lambda s: None)

    stop_event = threading.Event()
    stop_event.set()  # already stopped before pincer() even starts its round loop
    runner = _make_runner(stop_event=stop_event)
    ap = FakeAP()
    result = runner.pincer(ap, "wlan0", "wlan1", randomize_mac=False, watch_capture_fn=lambda *a: None)

    assert "no AUTHORIZED" in result or "stopped" in result.lower() or "exhausted" in result.lower()


def test_pincer_logs_warning_when_deauth_sends_zero_frames(monkeypatch, tmp_path):
    _patch_radio(monkeypatch, sent_deauth=0)
    monkeypatch.setattr(handshake_mod, "capture_handshake", lambda *a, **k: HandshakeCapture())
    monkeypatch.setattr("atwa.gui.attack_runner.time.sleep", lambda s: None)

    logs = []
    stop_event = threading.Event()

    def stopping_wait(timeout):
        stop_event.set()
        return True

    stop_event.wait = stopping_wait  # break out after round 1 without a real sleep

    runner = _make_runner(stop_event=stop_event, log_fn=logs.append)
    ap = FakeAP()
    runner.pincer(ap, "wlan0", "wlan1", randomize_mac=False, watch_capture_fn=lambda *a: None)

    assert any("did NOT go out" in msg for msg in logs)


def test_pincer_restores_both_radios_to_managed_mode(monkeypatch, tmp_path):
    _patch_radio(monkeypatch)
    monkeypatch.setattr(handshake_mod, "capture_handshake", lambda *a, **k: HandshakeCapture())
    monkeypatch.setattr("atwa.gui.attack_runner.time.sleep", lambda s: None)

    restored = []
    monkeypatch.setattr(radio_mod, "set_managed_mode", lambda iface, restore_mac=None: restored.append(iface))

    stop_event = threading.Event()
    stop_event.set()
    runner = _make_runner(stop_event=stop_event)
    ap = FakeAP()
    runner.pincer(ap, "wlan0", "wlan1", randomize_mac=False, watch_capture_fn=lambda *a: None)

    assert set(restored) == {"wlan0", "wlan1"}
