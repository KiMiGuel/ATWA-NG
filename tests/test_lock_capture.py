"""lock_capture.LockCapture: BSSID-match filtering and start/stop lifecycle.

Native replacement for the vendored airodump-ng "-c channel --bssid ..."
process the GUI's channel-lock feature used to spawn. AsyncSniffer/
PcapWriter are mocked out — this only tests the pure frame-matching logic
and that start()/stop() drive the sniffer and writer correctly.
"""
from __future__ import annotations

from atwa.frames import craft_auth, craft_beacon
from atwa.lock_capture import LockCapture


class FakeWriter:
    def __init__(self, *a, **kw):
        self.written = []
        self.closed = False

    def write(self, pkt):
        self.written.append(pkt)

    def close(self):
        self.closed = True


class FakeThread:
    def is_alive(self):
        return True


class FakeSniffer:
    def __init__(self, *a, **kw):
        self.started = False
        self.stopped = False
        self.thread = FakeThread()

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def _make_capture(monkeypatch, bssid="aa:bb:cc:dd:ee:ff"):
    import atwa.lock_capture as lock_capture_module

    monkeypatch.setattr(lock_capture_module, "PcapWriter", FakeWriter)
    monkeypatch.setattr(lock_capture_module, "AsyncSniffer", FakeSniffer)
    return LockCapture("wlan0mon", bssid, "/tmp/does-not-matter.pcap")


def test_matches_frame_addressed_to_from_or_as_bssid(monkeypatch):
    capture = _make_capture(monkeypatch)
    beacon = craft_beacon(bssid="AA:BB:CC:DD:EE:FF", ssid="test", channel=6)  # addr2/addr3 = bssid

    assert capture._matches(beacon) is True


def test_matches_is_case_insensitive(monkeypatch):
    capture = _make_capture(monkeypatch, bssid="AA:BB:CC:DD:EE:FF")
    beacon = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)

    assert capture._matches(beacon) is True


def test_does_not_match_unrelated_bssid(monkeypatch):
    capture = _make_capture(monkeypatch, bssid="aa:bb:cc:dd:ee:ff")
    other = craft_beacon(bssid="11:22:33:44:55:66", ssid="other", channel=6)

    assert capture._matches(other) is False


def test_matches_client_frame_to_ap(monkeypatch):
    capture = _make_capture(monkeypatch, bssid="aa:bb:cc:dd:ee:ff")
    # auth frame from a client addressed to the locked AP (addr1=bssid)
    frame = craft_auth(bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66")

    assert capture._matches(frame) is True


def test_on_packet_writes_only_matching_frames(monkeypatch):
    capture = _make_capture(monkeypatch, bssid="aa:bb:cc:dd:ee:ff")
    matching = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    other = craft_beacon(bssid="11:22:33:44:55:66", ssid="other", channel=6)

    capture._on_packet(matching)
    capture._on_packet(other)

    assert capture._writer.written == [matching]


def test_start_stop_lifecycle(monkeypatch):
    capture = _make_capture(monkeypatch)

    capture.start()
    assert capture._sniffer.started is True
    assert capture.is_running() is True

    capture.stop()
    assert capture._sniffer is None
    assert capture._writer.closed is True


def test_stop_before_start_does_not_raise(monkeypatch):
    capture = _make_capture(monkeypatch)

    capture.stop()  # must not raise even though start() was never called

    assert capture._writer.closed is True


def test_is_running_false_before_start(monkeypatch):
    capture = _make_capture(monkeypatch)

    assert capture.is_running() is False
