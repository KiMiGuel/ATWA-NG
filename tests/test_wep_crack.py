"""crack_wep's stop_event: confirmed live (2026-08-28) that Stop Attack on
a running WEP attack was a no-op until the full `timeout` (default 300s)
elapsed -- crack_wep took no stop_event at all. This checks the poll loop
now exits promptly once stop_event is set, same pattern as
test_online.py's test_online_guess_respects_stop_event."""
from __future__ import annotations

import threading

from atwa.attacks.wep_crack import crack_wep


def _noop_auth(iface, bssid, client, ssid, channel=None):
    pass


def test_crack_wep_respects_stop_event():
    stop_event = threading.Event()
    calls = []

    def fake_sniff(iface, timeout, prn, store):
        calls.append(timeout)
        stop_event.set()

    key = crack_wep(
        "mon0", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "TestNet", key_len=5,
        timeout=300.0, poll_interval=2.0,
        sniff_fn=fake_sniff, auth_fn=_noop_auth, stop_event=stop_event,
    )

    assert key is None
    assert len(calls) == 1  # loop exited after the first poll, not 150 of them


def test_crack_wep_without_stop_event_runs_until_timeout():
    """No stop_event passed -> unchanged behavior, loop runs on time/target-
    sessions alone (matches every existing caller) -- a short real timeout
    so this stays fast without needing to mock time.monotonic."""
    calls = []

    def fake_sniff(iface, timeout, prn, store):
        calls.append(timeout)

    key = crack_wep(
        "mon0", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "TestNet", key_len=5,
        timeout=0.05, poll_interval=0.01,
        sniff_fn=fake_sniff, auth_fn=_noop_auth,
    )

    assert key is None
    assert len(calls) >= 1
