"""OmniOrchestrator._stage_wep and the run()/run_smart() WEP short-circuit:
AP-directed ARP replay (crack_wep) first, Caffe Latte fallback only when no
seed frame ever appeared AND a client is visible -- dependency-injected the
same way every other stage in omni.py is (see the module's own docstring)."""
from __future__ import annotations

import threading

import pytest

import atwa.omni as omni_module
from atwa.omni import OmniOrchestrator, OmniReport, StageResult
from atwa.scan import AccessPoint


@pytest.fixture(autouse=True)
def _fake_get_mac(monkeypatch):
    monkeypatch.setattr(omni_module, "get_mac", lambda iface: "11:22:33:44:55:66")


def _ap(**overrides):
    defaults = dict(bssid="aa:bb:cc:dd:ee:ff", ssid="TestNet", channel=6, security="WEP", pmf="none")
    defaults.update(overrides)
    return AccessPoint(**defaults)


def _orch(crack_wep_fn=None, caffe_latte_fn=None, stop_event=None, **kw):
    return OmniOrchestrator(
        "mon0",
        crack_wep_fn=crack_wep_fn or (lambda *a, **kw: None),
        caffe_latte_fn=caffe_latte_fn or (lambda *a, **kw: None),
        stop_event=stop_event,
        **kw,
    )


def test_wep_stage_skips_when_already_stopped():
    stop_event = threading.Event()
    stop_event.set()
    orch = _orch(stop_event=stop_event)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    orch._stage_wep(_ap(), report)
    stage = report.stages[-1]
    assert stage.result is StageResult.SKIPPED
    assert stage.detail == "stopped"


def test_wep_stage_succeeds_via_arp_replay_without_trying_caffe_latte():
    caffe_calls = []

    def fake_crack_wep(iface, bssid, client, ssid, key_len, channel, stop_event, progress_fn, result_out):
        result_out["seed_found"] = True
        return b"\x01\x02\x03\x04\x05"

    def fake_caffe_latte(*a, **kw):
        caffe_calls.append(True)
        return None

    orch = _orch(crack_wep_fn=fake_crack_wep, caffe_latte_fn=fake_caffe_latte)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    ok = orch._stage_wep(_ap(clients={"11:22:33:44:55:66"}), report)

    assert ok is True
    assert report.cracked["aa:bb:cc:dd:ee:ff"] == "0102030405"
    assert report.stages[-1].result is StageResult.SUCCESS
    assert caffe_calls == []  # ARP replay succeeded -- Caffe Latte fallback never needed


def test_wep_stage_falls_back_to_caffe_latte_when_no_seed_found():
    def fake_crack_wep(iface, bssid, client, ssid, key_len, channel, stop_event, progress_fn, result_out):
        result_out["seed_found"] = False
        return None

    def fake_caffe_latte(iface, client_mac, key_len, channel, stop_event, progress_fn):
        assert client_mac == "aa:aa:aa:aa:aa:aa"
        return b"\xaa\xbb\xcc\xdd\xee"

    orch = _orch(crack_wep_fn=fake_crack_wep, caffe_latte_fn=fake_caffe_latte)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    ok = orch._stage_wep(_ap(clients={"aa:aa:aa:aa:aa:aa"}), report)

    assert ok is True
    assert report.cracked["aa:bb:cc:dd:ee:ff"] == "aabbccddee"
    assert "Caffe Latte" in report.stages[-1].detail


def test_wep_stage_does_not_try_caffe_latte_when_seed_was_found_but_key_failed():
    """A seed WAS found -- the failure is "not enough sessions yet", not
    "AP produced nothing" -- Caffe Latte's different capture path wouldn't
    help, so it must not be tried."""
    caffe_calls = []

    def fake_crack_wep(iface, bssid, client, ssid, key_len, channel, stop_event, progress_fn, result_out):
        result_out["seed_found"] = True
        return None

    def fake_caffe_latte(*a, **kw):
        caffe_calls.append(True)
        return b"\x01\x02\x03\x04\x05"

    orch = _orch(crack_wep_fn=fake_crack_wep, caffe_latte_fn=fake_caffe_latte)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    ok = orch._stage_wep(_ap(clients={"11:22:33:44:55:66"}), report)

    assert ok is False
    assert report.cracked == {}
    assert caffe_calls == []
    assert "not enough sessions" in report.stages[-1].detail


def test_wep_stage_fails_when_no_seed_and_no_client_seen():
    def fake_crack_wep(iface, bssid, client, ssid, key_len, channel, stop_event, progress_fn, result_out):
        result_out["seed_found"] = False
        return None

    orch = _orch(crack_wep_fn=fake_crack_wep)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    ok = orch._stage_wep(_ap(clients=set()), report)

    assert ok is False
    assert "no client seen" in report.stages[-1].detail


def test_run_short_circuits_to_wep_stage_for_wep_security():
    pmkid_calls = []

    def fake_crack_wep(*a, **kw):
        return b"\x01\x02\x03\x04\x05"

    orch = _orch(
        crack_wep_fn=fake_crack_wep,
        pmkid_fn=lambda *a, **kw: pmkid_calls.append(True),
    )
    report = orch.run(_ap())

    assert report.cracked["aa:bb:cc:dd:ee:ff"] == "0102030405"
    assert pmkid_calls == []  # WEP short-circuits before the WPA-oriented chain
    assert [s.name for s in report.stages] == ["profile", "wep"]


def test_run_smart_short_circuits_to_wep_stage_for_wep_security():
    def fake_crack_wep(*a, **kw):
        return b"\x01\x02\x03\x04\x05"

    orch = _orch(crack_wep_fn=fake_crack_wep)
    report = orch.run_smart(_ap())

    assert report.cracked["aa:bb:cc:dd:ee:ff"] == "0102030405"
    assert [s.name for s in report.stages] == ["profile", "wep"]
