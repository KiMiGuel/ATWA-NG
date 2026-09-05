"""attacks/eviltwin.py's run_owe_downgrade() -- the OWE (Enhanced Open)
transition-mode downgrade (secure.py's owe_downgrade recommendation).
All subprocess/radio calls are mocked; nothing here touches real
hardware."""

from __future__ import annotations

import threading

import atwa.attacks.eviltwin as eviltwin_mod
from atwa.attacks.eviltwin import OweDowngradeResult, run_owe_downgrade

# Captured before any test patches eviltwin_mod.time.sleep -- eviltwin_mod.time
# IS the real stdlib time module (a shared singleton via sys.modules), so
# monkeypatching one of its attributes mutates it for every other reference
# to that same module, including a fresh `import time` done later. Holding
# the real function object directly, not a module reference, sidesteps that.
_REAL_SLEEP = eviltwin_mod.time.sleep


class _FakeProc:
    def __init__(self, alive=True):
        self.pid = 12345
        self._alive = alive

    def poll(self):
        return None if self._alive else 1


class _FakeTempFile:
    def __init__(self):
        self.name = "/tmp/fake_owe.conf"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def write(self, data):
        pass


def _fake_tempfile(*args, **kwargs):
    return _FakeTempFile()


def _patch_common(monkeypatch, *, hostapd_alive=True):
    monkeypatch.setattr(eviltwin_mod, "_assign_ip", lambda iface: True)
    monkeypatch.setattr(eviltwin_mod, "_flush_ip", lambda iface: None)
    monkeypatch.setattr(eviltwin_mod, "_iptables_nat_add", lambda ap, mon: None)
    monkeypatch.setattr(eviltwin_mod, "_iptables_nat_remove", lambda ap, mon: None)
    monkeypatch.setattr(eviltwin_mod, "_popen", lambda cmd: _FakeProc(alive=hostapd_alive))
    monkeypatch.setattr(eviltwin_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(eviltwin_mod.os, "killpg", lambda *a, **k: None)
    monkeypatch.setattr(eviltwin_mod.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(eviltwin_mod.tempfile, "NamedTemporaryFile", _fake_tempfile)
    monkeypatch.setattr(eviltwin_mod.os, "unlink", lambda path: None)


def test_owe_downgrade_reports_hostapd_failure_cleanly(monkeypatch):
    _patch_common(monkeypatch, hostapd_alive=False)
    result = run_owe_downgrade(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeOpen", 6,
    )
    assert isinstance(result, OweDowngradeResult)
    assert result.success is False
    assert "hostapd" in result.detail.lower()


def test_owe_downgrade_reports_assign_ip_failure_cleanly(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_assign_ip", lambda iface: False)
    result = run_owe_downgrade(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeOpen", 6,
    )
    assert result.success is False
    assert "ip" in result.detail.lower()


def test_owe_downgrade_reports_no_client_associated(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_deauth", lambda *a, **k: 64)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: [])

    stop_event = threading.Event()
    stop_event.set()  # already stopped -- loop exits immediately, nobody associated
    result = run_owe_downgrade(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeOpen", 6,
        stop_event=stop_event,
    )
    assert result.success is False
    assert result.client_mac is None
    assert "no client" in result.detail.lower()


def test_owe_downgrade_reports_success_on_client_association(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod, "_deauth", lambda *a, **k: 64)
    monkeypatch.setattr(eviltwin_mod, "_station_dump", lambda iface: ["11:22:33:44:55:66"])

    result = run_owe_downgrade(
        "wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeOpen", 6, timeout=5.0,
    )
    assert result.success is True
    assert result.client_mac == "11:22:33:44:55:66"
    assert "downgraded" in result.detail.lower()


def test_owe_downgrade_deauths_the_real_owe_bssid_not_the_open_twin(monkeypatch):
    """The deauth loop must target owe_bssid (the real OWE AP), never the
    rogue open twin we're broadcasting -- deauthing our own AP would be
    self-defeating.

    _patch_common() mocks time.sleep to a no-op, which is fine for tests
    where the poll loop's own exit condition doesn't race a background
    thread -- but here it would let the main thread return before the
    daemon deauth thread ever gets scheduled at all. Restore a real
    (tiny) sleep for this one test so the OS scheduler gets a genuine
    chance to run it, same reasoning as why run_downgrade_twin's own
    tests rely on a real multi-second time.monotonic() deadline rather
    than an artificial hook."""
    _patch_common(monkeypatch)
    monkeypatch.setattr(eviltwin_mod.time, "sleep", lambda s: _REAL_SLEEP(0.01))
    calls = {"n": 0}

    def fake_station_dump(iface):
        calls["n"] += 1
        return ["11:22:33:44:55:66"] if calls["n"] > 3 else []

    monkeypatch.setattr(eviltwin_mod, "_station_dump", fake_station_dump)
    deauth_targets = []

    def fake_deauth(iface, bssid, **kwargs):
        deauth_targets.append(bssid)
        return 64

    monkeypatch.setattr(eviltwin_mod, "_deauth", fake_deauth)

    run_owe_downgrade("wlan1", "wlan0", "aa:bb:cc:dd:ee:ff", "HomeOpen", 6, timeout=5.0)

    assert deauth_targets
    assert all(t == "aa:bb:cc:dd:ee:ff" for t in deauth_targets)
