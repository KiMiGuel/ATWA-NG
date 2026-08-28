"""attacks/handshake.py: capture_handshake() must (1) grab exactly one
beacon/probe-response frame alongside the EAPOL frames -- hcxpcapngtool
refuses to convert an EAPOL-only capture since the ESSID (mandatory for
PMK computation) only lives in a beacon/probe-response, confirmed live
2026-08-27 -- and (2) discard the output file entirely when nothing at
all was captured, so a folder of failed deauth rounds doesn't fill up
with empty pcaps. CHALLENGE-only captures (M1+M2, no M3) must NOT be
discarded -- that's still real, potentially crackable material, just
unverified by the AP."""
from __future__ import annotations

from typing import ClassVar

from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL, EAPOL_KEY

import atwa.attacks.handshake as hs_module
from atwa.frames import craft_beacon


class FakeWriter:
    instances: ClassVar[list] = []

    def __init__(self, *a, **kw):
        self.written = []
        self.closed = False
        FakeWriter.instances.append(self)

    def write(self, pkt):
        self.written.append(pkt)

    def close(self):
        self.closed = True


class FakeThread:
    def __init__(self):
        self.alive = True

    def is_alive(self):
        return self.alive


class FakeSniffer:
    """Feeds every packet in `pending` to prn() during start(), then marks
    itself stopped so capture_handshake()'s poll loop exits on its very
    first check -- no real sleeping needed for a fast, deterministic test."""

    pending: ClassVar[list] = []

    def __init__(self, iface, prn, stop_filter, store):
        self.prn = prn
        self.stop_filter = stop_filter
        self.thread = FakeThread()

    def start(self):
        for pkt in FakeSniffer.pending:
            self.prn(pkt)
        self.thread.alive = False

    def stop(self):
        pass


def _eapol_frame(bssid: str, client: str, msg_no: int):
    """A minimal 802.11 data frame carrying an EAPOL-Key message msg_no (1-3)."""
    if msg_no == 1:
        addr1, addr2, key = client, bssid, EAPOL_KEY(key_ack=1, has_key_mic=0)
    elif msg_no == 2:
        addr1, addr2, key = bssid, client, EAPOL_KEY(key_ack=0, has_key_mic=1)
    else:
        addr1, addr2, key = client, bssid, EAPOL_KEY(key_ack=1, has_key_mic=1)
    dot11 = Dot11(type=2, subtype=0, addr1=addr1, addr2=addr2, addr3=bssid)
    return dot11 / EAPOL(version=1, type=3) / key


def _run_capture(monkeypatch, tmp_path, packets, timeout=5.0):
    FakeSniffer.pending = packets
    FakeWriter.instances = []
    monkeypatch.setattr(hs_module, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(hs_module, "PcapWriter", FakeWriter)
    monkeypatch.setattr(hs_module, "ensure_channel", lambda *a, **kw: False)
    outfile = tmp_path / "out.pcap"
    outfile.touch()  # PcapWriter is faked -- a real file must exist for unlink() to remove
    messages = []
    cap = hs_module.capture_handshake(
        "wlan0mon", "aa:bb:cc:dd:ee:ff", timeout=timeout,
        outfile=str(outfile), progress_fn=messages.append,
    )
    writer = FakeWriter.instances[-1]
    return cap, outfile, writer, messages


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def test_beacon_captured_alongside_challenge_eapol(monkeypatch, tmp_path):
    beacon = craft_beacon(bssid=BSSID, ssid="test", channel=6)
    m1 = _eapol_frame(BSSID, CLIENT, 1)
    m2 = _eapol_frame(BSSID, CLIENT, 2)

    cap, outfile, writer, _ = _run_capture(monkeypatch, tmp_path, [beacon, m1, m2])

    assert cap.status(BSSID, CLIENT).value == "challenge"
    assert beacon in writer.written
    assert m1 in writer.written and m2 in writer.written
    assert outfile.exists()  # real (if unverified) material must be kept


def test_only_one_beacon_written_even_with_several_seen(monkeypatch, tmp_path):
    beacon1 = craft_beacon(bssid=BSSID, ssid="test", channel=6)
    beacon2 = craft_beacon(bssid=BSSID, ssid="test", channel=6)
    m1 = _eapol_frame(BSSID, CLIENT, 1)

    _, _, writer, _ = _run_capture(monkeypatch, tmp_path, [beacon1, m1, beacon2])

    from atwa.frames import Dot11Beacon
    beacon_count = sum(1 for pkt in writer.written if pkt.haslayer(Dot11Beacon))
    assert beacon_count == 1


def test_authorized_capture_keeps_file(monkeypatch, tmp_path):
    packets = [
        craft_beacon(bssid=BSSID, ssid="test", channel=6),
        _eapol_frame(BSSID, CLIENT, 1),
        _eapol_frame(BSSID, CLIENT, 2),
        _eapol_frame(BSSID, CLIENT, 3),
    ]

    cap, outfile, _, messages = _run_capture(monkeypatch, tmp_path, packets)

    assert cap.status(BSSID, CLIENT).value == "authorized"
    assert outfile.exists()
    assert not any("discarded empty capture file" in m for m in messages)


def test_empty_capture_discards_file(monkeypatch, tmp_path):
    # A round where the deauth went out but nobody ever reconnected -- only
    # the AP's own beacons show up, zero EAPOL activity.
    packets = [craft_beacon(bssid=BSSID, ssid="test", channel=6)]

    cap, outfile, _, messages = _run_capture(monkeypatch, tmp_path, packets)

    assert not cap.messages
    assert not outfile.exists()
    assert any("discarded empty capture file" in m for m in messages)


def test_completely_silent_capture_discards_file(monkeypatch, tmp_path):
    cap, outfile, _, messages = _run_capture(monkeypatch, tmp_path, [])

    assert not cap.messages
    assert not outfile.exists()
    assert any("no EAPOL frames seen" in m for m in messages)
    assert any("discarded empty capture file" in m for m in messages)


def test_no_outfile_skips_delete_logic_cleanly(monkeypatch):
    FakeSniffer.pending = []
    monkeypatch.setattr(hs_module, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(hs_module, "ensure_channel", lambda *a, **kw: False)

    cap = hs_module.capture_handshake("wlan0mon", BSSID, timeout=5.0, outfile=None)

    assert not cap.messages  # must not raise despite no file to delete
