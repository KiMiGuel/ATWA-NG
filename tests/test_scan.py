"""scan.process_packet: AccessPoint.signal is a running best-ever max (for
the target list's sort/display column); last_signal is the latest reading
(for a live rolling time-series graph) -- see gui/widgets.SignalGraph.
Conflating the two made the GUI's signal graph plateau after the first
strong reading instead of tracking live RSSI."""
from __future__ import annotations

from scapy.layers.dot11 import RadioTap

from atwa.frames import craft_beacon, craft_probe_resp
from atwa.radio import ALL_CHANNELS, CHANNELS_24GHZ, CHANNELS_5GHZ
from atwa.scan import ScanResult, channels_for_band, process_packet


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


# --- beacon_count / first_seen / last_seen (native replacement for the old
# airodump-ng CSV's "# beacons" and First/Last time seen columns) -----------


def test_beacon_count_increments_only_for_beacon_frames():
    result = ScanResult()
    beacon = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    probe_resp = craft_probe_resp(bssid="aa:bb:cc:dd:ee:ff", ssid="test", client="11:22:33:44:55:66", channel=6)

    process_packet(beacon, result)
    process_packet(beacon, result)
    process_packet(probe_resp, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.beacon_count == 2  # probe response must not count as a beacon


def test_beacon_count_starts_at_zero_for_new_ap():
    result = ScanResult()
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)

    process_packet(pkt, result)

    assert result.aps["aa:bb:cc:dd:ee:ff"].beacon_count == 1


def test_first_seen_set_once_last_seen_updates():
    """Real wall-clock timestamps, not a monkeypatched time.time(): scapy's
    own Packet internals call time.time() too (packet construction, field
    generators), so patching the shared stdlib module is unsafe here."""
    import time as real_time

    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    result = ScanResult()

    process_packet(pkt, result)
    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    first_seen_initial = ap.first_seen
    assert first_seen_initial is not None

    real_time.sleep(0.01)
    process_packet(pkt, result)

    assert ap.first_seen == first_seen_initial  # unchanged on repeat sightings
    assert ap.last_seen > first_seen_initial  # advances on repeat sightings


# --- channels_for_band: native replacement for airodump-ng's --band flag ---


def test_channels_for_band_24ghz():
    assert channels_for_band("2.4GHz") == CHANNELS_24GHZ


def test_channels_for_band_5ghz():
    assert channels_for_band("5GHz") == CHANNELS_5GHZ


def test_channels_for_band_both():
    assert channels_for_band("Both") == ALL_CHANNELS


def test_channels_for_band_unknown_defaults_to_all():
    assert channels_for_band("60GHz-typo") == ALL_CHANNELS
