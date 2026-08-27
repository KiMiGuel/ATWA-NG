"""scan.process_packet: AccessPoint.signal is a running best-ever max (for
the target list's sort/display column); last_signal is the latest reading
(for a live rolling time-series graph) -- see gui/widgets.SignalGraph.
Conflating the two made the GUI's signal graph plateau after the first
strong reading instead of tracking live RSSI."""
from __future__ import annotations

from scapy.layers.dot11 import RadioTap

from atwa.frames import craft_beacon
from atwa.scan import ScanResult, process_packet


def _beacon_with_signal(dbm: int):
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    rtap = pkt.getlayer(RadioTap)
    rtap.present = "dBm_AntSignal"
    rtap.dBm_AntSignal = dbm
    return pkt


def test_signal_is_running_max_last_signal_is_latest():
    result = ScanResult()

    process_packet(_beacon_with_signal(-40), result)
    process_packet(_beacon_with_signal(-70), result)
    process_packet(_beacon_with_signal(-55), result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.signal == -40  # best-ever seen, never regresses
    assert ap.last_signal == -55  # most recent reading, tracks the drop


def test_last_signal_none_when_no_dbm_reported():
    result = ScanResult()
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)

    process_packet(pkt, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.signal is None
    assert ap.last_signal is None
