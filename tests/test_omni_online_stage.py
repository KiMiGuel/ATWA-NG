"""OmniOrchestrator._stage_online: skip conditions + success/failure
wiring, via a fake online_fn (dependency-injected the same way every
other stage in omni.py is -- see the module's own docstring)."""
from __future__ import annotations

import pytest

import atwa.omni as omni_module
from atwa.attacks.online import OnlineGuessResult
from atwa.omni import OmniOrchestrator, OmniReport, StageResult
from atwa.scan import AccessPoint


@pytest.fixture(autouse=True)
def _fake_get_mac(monkeypatch):
    """_stage_online looks up the interface's own MAC for the client role
    -- stub it so these tests don't depend on a real 'mon0' interface
    existing on whatever machine runs the suite."""
    monkeypatch.setattr(omni_module, "get_mac", lambda iface: "11:22:33:44:55:66")


def _ap(**overrides):
    defaults = dict(bssid="aa:bb:cc:dd:ee:ff", ssid="TestNet", channel=6, security="WPA2", pmf="none")
    defaults.update(overrides)
    return AccessPoint(**defaults)


def _orch(online_fn=None, stop_event=None):
    return OmniOrchestrator("mon0", online_fn=online_fn or (lambda *a, **kw: OnlineGuessResult(success=False)), stop_event=stop_event)


def test_online_stage_skips_when_material_already_captured():
    orch = _orch()
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(), report, material_captured=True, wordlist="/tmp/wl.txt")
    stage = report.stages[-1]
    assert stage.name == "online"
    assert stage.result is StageResult.SKIPPED
    assert "capture material" in stage.detail


def test_online_stage_skips_without_a_wordlist():
    orch = _orch()
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(), report, material_captured=False, wordlist=None)
    stage = report.stages[-1]
    assert stage.result is StageResult.SKIPPED
    assert "wordlist" in stage.detail


def test_online_stage_skips_wpa3_sae_only():
    orch = _orch()
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(security="WPA3"), report, material_captured=False, wordlist="/tmp/wl.txt")
    stage = report.stages[-1]
    assert stage.result is StageResult.SKIPPED
    assert "WPA3" in stage.detail


def test_online_stage_allows_transition_security():
    """'transition' (SAE+PSK) still has a PSK AKM present -- should reach
    the online_fn, not be skipped as unsupported."""
    calls = []

    def fake_online_fn(*a, **kw):
        calls.append(True)
        return OnlineGuessResult(success=False, detail="wordlist exhausted after 0 attempt(s)")

    orch = _orch(online_fn=fake_online_fn)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(security="transition"), report, material_captured=False, wordlist="/tmp/wl.txt")
    assert calls == [True]


def test_online_stage_skips_when_already_stopped():
    import threading

    stop_event = threading.Event()
    stop_event.set()
    orch = _orch(stop_event=stop_event)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(), report, material_captured=False, wordlist="/tmp/wl.txt")
    stage = report.stages[-1]
    assert stage.result is StageResult.SKIPPED
    assert stage.detail == "stopped"


def test_online_stage_records_success_and_populates_cracked():
    def fake_online_fn(iface, bssid, ssid, client, wordlist, **kw):
        return OnlineGuessResult(success=True, password="hunter2plus", attempts=3, detail="AP confirmed Message 3")

    orch = _orch(online_fn=fake_online_fn)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(), report, material_captured=False, wordlist="/tmp/wl.txt")

    assert report.cracked["aa:bb:cc:dd:ee:ff"] == "hunter2plus"
    stage = report.stages[-1]
    assert stage.result is StageResult.SUCCESS
    assert "hunter2plus" in stage.detail


def test_online_stage_records_failure_without_touching_cracked():
    def fake_online_fn(iface, bssid, ssid, client, wordlist, **kw):
        return OnlineGuessResult(success=False, attempts=5, detail="wordlist exhausted after 5 attempt(s)")

    orch = _orch(online_fn=fake_online_fn)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(), report, material_captured=False, wordlist="/tmp/wl.txt")

    assert report.cracked == {}
    stage = report.stages[-1]
    assert stage.result is StageResult.FAILED
    assert "5 attempt" in stage.detail


def test_online_stage_passes_channel_and_budget_through(monkeypatch):
    captured_kwargs = {}

    def fake_online_fn(iface, bssid, ssid, client, wordlist, **kw):
        captured_kwargs.update(kw)
        return OnlineGuessResult(success=False)

    orch = OmniOrchestrator("mon0", online_fn=fake_online_fn, online_max_attempts=7)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_online(_ap(channel=11), report, material_captured=False, wordlist="/tmp/wl.txt")

    assert captured_kwargs["channel"] == 11
    assert captured_kwargs["max_attempts"] == 7
