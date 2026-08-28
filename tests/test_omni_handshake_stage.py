"""OmniOrchestrator._stage_handshake + run(): CHALLENGE-only (M1+M2,
unverified by the AP) capture material must be treated as genuinely
crackable, not discarded.

Live-verified 2026-08-27: hcxpcapngtool converted a real CHALLENGE-only
pair sitting in the same file as an AUTHORIZED one into a valid 22000
hash line -- offline WPA cracking has never needed M3, only the
orchestrator's own bookkeeping used to (wrongly) assume otherwise.
"""
from __future__ import annotations

import atwa.omni as omni_module
from atwa.attacks.handshake import HandshakeCapture
from atwa.attacks.online import OnlineGuessResult
from atwa.omni import OmniOrchestrator, OmniReport, StageResult
from atwa.scan import AccessPoint

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def _ap(**overrides):
    defaults = {"bssid": BSSID, "ssid": "TestNet", "channel": 6, "security": "WPA2", "pmf": "none"}
    defaults.update(overrides)
    return AccessPoint(**defaults)


def _orch(handshake_fn, online_fn=None):
    return OmniOrchestrator(
        "mon0",
        handshake_fn=handshake_fn,
        deauth_fn=lambda *a, **kw: 64,
        online_fn=online_fn or (lambda *a, **kw: OnlineGuessResult(success=False)),
        handshake_max_rounds=1,
        # NOT 0 -- omni.py's constructor does `handshake_round_interval or
        # self.HANDSHAKE_ROUND_INTERVAL`, and 0 is falsy in Python, so a
        # literal 0 here silently becomes the real 15.0s default instead
        # (learned the hard way: these tests took 45s before this fix).
        handshake_round_interval=0.01,
        listener_settle=0,
    )


def _cap_with(*msg_nos: int) -> HandshakeCapture:
    cap = HandshakeCapture()
    for n in msg_nos:
        cap.add(BSSID, CLIENT, n)
    return cap


def test_challenge_only_is_treated_as_success_and_feeds_crack(monkeypatch):
    orch = _orch(handshake_fn=lambda *a, **kw: _cap_with(1, 2))
    report = OmniReport(target=BSSID)

    status = orch._stage_handshake(_ap(), report)

    stage = report.stages[-1]
    assert status.value == "challenge"
    assert stage.name == "handshake"
    assert stage.result is StageResult.SUCCESS
    assert "CHALLENGE" in stage.detail
    assert report.hash_lines  # must be fed to _stage_crack, not discarded


def test_authorized_still_treated_as_success_and_feeds_crack(monkeypatch):
    orch = _orch(handshake_fn=lambda *a, **kw: _cap_with(1, 2, 3))
    report = OmniReport(target=BSSID)

    status = orch._stage_handshake(_ap(), report)

    stage = report.stages[-1]
    assert status.value == "authorized"
    assert stage.result is StageResult.SUCCESS
    assert report.hash_lines


def test_no_eapol_at_all_stays_failed_and_empty(monkeypatch):
    orch = _orch(handshake_fn=lambda *a, **kw: HandshakeCapture())
    report = OmniReport(target=BSSID)

    status = orch._stage_handshake(_ap(), report)

    stage = report.stages[-1]
    assert status.value == "none"
    assert stage.result is StageResult.FAILED
    assert not report.hash_lines


def test_run_skips_online_stage_when_challenge_only_material_captured(monkeypatch):
    monkeypatch.setattr(omni_module, "get_mac", lambda iface: CLIENT)
    online_calls = []

    def spy_online(*a, **kw):
        online_calls.append((a, kw))
        return OnlineGuessResult(success=False)

    orch = _orch(handshake_fn=lambda *a, **kw: _cap_with(1, 2), online_fn=spy_online)
    monkeypatch.setattr(orch, "_stage_pmkid", lambda ap, report: False)
    monkeypatch.setattr(orch, "_stage_wps", lambda ap, report: False)
    monkeypatch.setattr(orch, "_stage_eviltwin", lambda ap, report: None)
    monkeypatch.setattr(orch, "_stage_profile", lambda ap, report: None)
    monkeypatch.setattr(orch, "_stage_crack", lambda report, wordlist: None)

    report = orch.run(_ap(), wordlist="/tmp/wl.txt")

    online_stage = next(s for s in report.stages if s.name == "online")
    assert online_stage.result is StageResult.SKIPPED
    assert "capture material" in online_stage.detail
    assert online_calls == []  # the online_fn itself must never have been invoked
